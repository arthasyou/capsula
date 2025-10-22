use std::collections::HashSet;

use capsula_core::CapsuleContent;
use chrono::{DateTime, FixedOffset};
use model_gateway_rs::{
    model::llm::{ChatMessage, LlmInput, LlmOutput},
    traits::ModelClient,
};
use serde_json::{json, Value};

use super::capsula_util::DecryptedCapsule;
use crate::error::{AppError, Result};

const DEFAULT_SYSTEM_PROMPT: &str = include_str!("../../prompts/cap1_level1_summary.md");

/// Level 0 视图：返回原始 Cap1 胶囊的主要内容，不做额外加工。
pub fn project_cap1_level0(capsules: &[DecryptedCapsule]) -> Value {
    let capsules = collect_cap1_records(capsules)
        .into_iter()
        .map(|record| {
            json!({
                "capsule_id": record.capsule.capsule_id.clone(),
                "owner_id": record.capsule.owner_id.clone(),
                "content_type": record.capsule.content_type.clone(),
                "created_at": record.capsule.created_at,
                "source_cap0": record.cap0_id,
                "meta_data": String::from_utf8_lossy(record.meta_data).into_owned(),
                "bnf_extract_data": String::from_utf8_lossy(record.bnf_extract_data).into_owned(),
            })
        })
        .collect::<Vec<_>>();

    json!({
        "capsule_count": capsules.len(),
        "capsules": capsules,
    })
}

/// LLM 请求配置选项
#[derive(Debug, Clone)]
pub struct Level1LlmOptions {
    pub system_prompt: Option<String>,
    pub max_tokens: Option<u32>,
}

impl Default for Level1LlmOptions {
    fn default() -> Self {
        Self {
            system_prompt: None,
            max_tokens: Some(800),
        }
    }
}

/// Level 1 视图：将 Cap1 胶囊数据聚合后交给 LLM 进行总结
pub async fn summarize_cap1_level1_with_llm<C>(
    capsules: &[DecryptedCapsule],
    client: &C,
    options: Level1LlmOptions,
) -> Result<Value>
where
    C: ModelClient<LlmInput, LlmOutput> + Sync + Send,
{
    let records = collect_cap1_records(capsules);
    let dataset = build_level1_dataset(&records)?;

    if records.is_empty() {
        return Ok(json!({
            "aggregate": dataset,
            "llm_summary": "未找到可用于分析的 Cap1 数据胶囊。",
        }));
    }

    let dataset_json = serde_json::to_string_pretty(&dataset)
        .map_err(|e| AppError::Internal(format!("Failed to serialize Level1 dataset: {}", e)))?;

    let system_prompt = options
        .system_prompt
        .unwrap_or_else(|| DEFAULT_SYSTEM_PROMPT.to_string());

    let user_prompt = format!(
        "以下是多个 1 阶数据胶囊的综合信息，请基于这些内容给出中文总结，强调异常指标、\
         整体风险与建议：\n```json\n{}\n```",
        dataset_json
    );

    let input = LlmInput {
        messages: vec![
            ChatMessage::system(&system_prompt),
            ChatMessage::user(&user_prompt),
        ],
        max_tokens: options.max_tokens.or(Some(800)),
    };

    let response = client
        .infer(input)
        .await
        .map_err(|e| AppError::Internal(format!("LLM inference failed: {}", e)))?;

    let raw_summary = response.get_content().trim();
    if raw_summary.is_empty() {
        return Err(AppError::Internal(
            "LLM returned empty response for Level 1 summary".to_string(),
        ));
    }

    let llm_summary: Value = serde_json::from_str(raw_summary).map_err(|e| {
        AppError::Internal(format!(
            "LLM response is not valid JSON: {}. Raw output: {}",
            e, raw_summary
        ))
    })?;

    Ok(json!({
        "dataset": dataset,
        "llm_summary": llm_summary,
    }))
}

struct Cap1Record<'a> {
    capsule: &'a DecryptedCapsule,
    cap0_id: &'a str,
    meta_data: &'a [u8],
    bnf_extract_data: &'a [u8],
}

fn collect_cap1_records(capsules: &[DecryptedCapsule]) -> Vec<Cap1Record<'_>> {
    capsules
        .iter()
        .filter_map(|capsule| match &capsule.content {
            CapsuleContent::Cap1Content {
                cap0_id,
                meta_data,
                bnf_extract_data,
            } => Some(Cap1Record {
                capsule,
                cap0_id: cap0_id.as_str(),
                meta_data: meta_data.as_slice(),
                bnf_extract_data: bnf_extract_data.as_slice(),
            }),
            _ => None,
        })
        .collect()
}

fn build_level1_dataset(records: &[Cap1Record<'_>]) -> Result<Value> {
    let mut aggregate_counts = StatusCounts::default();
    let mut severity_counts = SeverityCounts::default();
    let mut owner_ids = HashSet::new();
    let mut categories = HashSet::new();
    let mut timeline = TimeRange::default();

    let mut capsule_summaries = Vec::new();

    for record in records {
        owner_ids.insert(record.capsule.owner_id.clone());

        let meta = parse_json_bytes(record.meta_data, "cap1 meta_data")?;
        let bnf = parse_json_bytes(record.bnf_extract_data, "cap1 bnf_extract_data")?;
        let status_counts = compute_status_counts(&bnf);

        aggregate_counts.accumulate(&status_counts);

        let severity = if status_counts.critical > 0 {
            severity_counts.critical += 1;
            "critical"
        } else if status_counts.abnormal > 0 {
            severity_counts.abnormal += 1;
            "abnormal"
        } else {
            severity_counts.normal += 1;
            "normal"
        };

        for category in collect_categories(&bnf) {
            categories.insert(category);
        }

        timeline.update(&meta, &bnf);

        let meta_overview = extract_meta_overview(&meta);
        let summary = bnf.get("summary").cloned().unwrap_or(Value::Null);
        let metadata = bnf.get("metadata").cloned().unwrap_or(Value::Null);
        let abnormal_indicators = collect_abnormal_indicator_details(&bnf);

        let capsule_summary = json!({
            "capsule_id": record.capsule.capsule_id,
            "source_cap0": record.cap0_id,
            "owner_id": record.capsule.owner_id,
            "content_type": record.capsule.content_type,
            "created_at": record.capsule.created_at,
            "severity": severity,
            "indicator_counts": {
                "total": status_counts.total,
                "normal": status_counts.normal,
                "abnormal": status_counts.abnormal,
                "critical": status_counts.critical,
            },
            "timeline": {
                "collected_at": extract_string(&meta, &["collection_info", "collected_at"]),
                "processed_at": extract_string(&meta, &["processing_info", "processed_at"]),
                "extracted_at": extract_string(&bnf, &["metadata", "extracted_at"]),
            },
            "meta_overview": meta_overview,
            "bnf_metadata": metadata,
            "summary": summary,
            "abnormal_indicators": abnormal_indicators,
        });

        capsule_summaries.push(capsule_summary);
    }

    capsule_summaries.sort_by(|a, b| {
        let a_ts = a
            .get("created_at")
            .and_then(|v| v.as_i64())
            .unwrap_or_default();
        let b_ts = b
            .get("created_at")
            .and_then(|v| v.as_i64())
            .unwrap_or_default();
        a_ts.cmp(&b_ts)
    });

    let mut owner_ids_vec: Vec<_> = owner_ids.into_iter().collect();
    owner_ids_vec.sort();

    let mut categories_vec: Vec<_> = categories.into_iter().collect();
    categories_vec.sort();

    Ok(json!({
        "aggregate": {
            "capsule_count": records.len(),
            "owner_ids": owner_ids_vec,
            "indicator_counts": {
                "total": aggregate_counts.total,
                "normal": aggregate_counts.normal,
                "abnormal": aggregate_counts.abnormal,
                "critical": aggregate_counts.critical,
            },
            "capsule_severity_counts": {
                "normal": severity_counts.normal,
                "abnormal": severity_counts.abnormal,
                "critical": severity_counts.critical,
            },
            "categories": categories_vec,
            "timeline": timeline.as_value(),
        },
        "capsules": capsule_summaries,
    }))
}

fn parse_json_bytes(bytes: &[u8], context: &str) -> Result<Value> {
    serde_json::from_slice(bytes).map_err(|e| {
        tracing::warn!("{} is not valid JSON: {}", context, e);
        AppError::Internal(format!("{} is not valid JSON: {}", context, e))
    })
}

fn extract_string(value: &Value, path: &[&str]) -> Option<String> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    current.as_str().map(|s| s.to_string())
}

fn extract_meta_overview(meta: &Value) -> Value {
    json!({
        "collector": meta.get("collector").cloned().unwrap_or(Value::Null),
        "owner": meta.get("owner").cloned().unwrap_or(Value::Null),
        "collection_info": meta.get("collection_info").cloned().unwrap_or(Value::Null),
        "processing_info": meta.get("processing_info").cloned().unwrap_or(Value::Null),
        "sensitivity": meta.get("sensitivity").cloned().unwrap_or(Value::Null),
    })
}

#[derive(Default, Clone, Copy)]
struct StatusCounts {
    total: usize,
    normal: usize,
    abnormal: usize,
    critical: usize,
}

impl StatusCounts {
    fn accumulate(&mut self, other: &StatusCounts) {
        self.total += other.total;
        self.normal += other.normal;
        self.abnormal += other.abnormal;
        self.critical += other.critical;
    }
}

fn compute_status_counts(bnf: &Value) -> StatusCounts {
    let mut counts = StatusCounts::default();

    if let Some(tests) = bnf.get("tests").and_then(|v| v.as_array()) {
        for category in tests {
            if let Some(items) = category.get("items").and_then(|v| v.as_array()) {
                for item in items {
                    counts.total += 1;
                    if let Some(status) = item.get("status").and_then(|v| v.as_str()) {
                        let status_lower = status.to_ascii_lowercase();
                        match status_lower.as_str() {
                            "normal" | "ok" => counts.normal += 1,
                            "abnormal" | "warning" => counts.abnormal += 1,
                            "critical" | "danger" => counts.critical += 1,
                            _ => {}
                        }
                    }
                }
            }
        }
    }

    counts
}

fn collect_categories(bnf: &Value) -> Vec<String> {
    if let Some(tests) = bnf.get("tests").and_then(|v| v.as_array()) {
        tests
            .iter()
            .filter_map(|category| {
                category
                    .get("category")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
            })
            .collect()
    } else {
        Vec::new()
    }
}

fn collect_abnormal_indicator_details(bnf: &Value) -> Vec<Value> {
    let mut indicators = Vec::new();

    if let Some(tests) = bnf.get("tests").and_then(|v| v.as_array()) {
        for category in tests {
            let category_name = category
                .get("category")
                .and_then(|v| v.as_str())
                .unwrap_or("未知项目");

            if let Some(items) = category.get("items").and_then(|v| v.as_array()) {
                for item in items {
                    let status = item
                        .get("status")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown");
                    if status.eq_ignore_ascii_case("normal") || status.eq_ignore_ascii_case("ok") {
                        continue;
                    }

                    indicators.push(json!({
                        "category": category_name,
                        "indicator": item.get("name").and_then(|v| v.as_str()),
                        "code": item.get("code").and_then(|v| v.as_str()),
                        "status": status,
                        "value": item.get("value"),
                        "unit": item.get("unit"),
                        "reference_range": item.get("reference_range"),
                        "flag": item.get("flag"),
                    }));
                }
            }
        }
    }

    indicators
}

#[derive(Default)]
struct SeverityCounts {
    normal: usize,
    abnormal: usize,
    critical: usize,
}

#[derive(Default)]
struct TimeRange {
    earliest: Option<(String, DateTime<FixedOffset>)>,
    latest: Option<(String, DateTime<FixedOffset>)>,
}

impl TimeRange {
    fn update(&mut self, meta: &Value, bnf: &Value) {
        let candidates = [
            extract_string(meta, &["collection_info", "collected_at"]),
            extract_string(meta, &["processing_info", "processed_at"]),
            extract_string(bnf, &["metadata", "extracted_at"]),
        ];

        for candidate in candidates {
            if let Some(ts) = candidate {
                if let Ok(parsed) = DateTime::parse_from_rfc3339(&ts) {
                    self.track(ts, parsed);
                }
            }
        }
    }

    fn track(&mut self, ts: String, parsed: DateTime<FixedOffset>) {
        match &mut self.earliest {
            Some((_, current)) if parsed < *current => {
                self.earliest = Some((ts.clone(), parsed));
            }
            None => {
                self.earliest = Some((ts.clone(), parsed));
            }
            _ => {}
        }

        match &mut self.latest {
            Some((_, current)) if parsed > *current => {
                self.latest = Some((ts, parsed));
            }
            None => {
                self.latest = Some((ts, parsed));
            }
            _ => {}
        }
    }

    fn as_value(&self) -> Value {
        match (&self.earliest, &self.latest) {
            (Some((earliest, _)), Some((latest, _))) => json!({
                "earliest": earliest,
                "latest": latest,
            }),
            (Some((earliest, _)), None) => json!({
                "earliest": earliest,
                "latest": earliest,
            }),
            (None, Some((latest, _))) => json!({
                "earliest": latest,
                "latest": latest,
            }),
            (None, None) => Value::Null,
        }
    }
}
