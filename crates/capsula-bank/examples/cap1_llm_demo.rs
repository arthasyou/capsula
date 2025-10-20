use capsula_bank::utils::{
    cap1_util::{project_cap1_level0, summarize_cap1_level1_with_llm, Level1LlmOptions},
    capsula_util::DecryptedCapsule,
};
use capsula_core::CapsuleContent;
use model_gateway_rs::{
    clients::llm::LlmClient,
    error::Result as GatewayResult,
    sdk::openai::OpenAiSdk,
};
use serde_json::json;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let capsules = sample_cap1_capsules();

    println!("=== Level 0 (Raw Capsules) ===");
    println!("{}", serde_json::to_string_pretty(&project_cap1_level0(&capsules))?);
    println!();

    let llm_client = create_ollama_client()?;
    let level1_view = summarize_cap1_level1_with_llm(
        &capsules,
        &llm_client,
        Level1LlmOptions {
            system_prompt: None,
            max_tokens: Some(600),
        },
    )
    .await?;

    println!("=== Level 1 (LLM JSON Summary) ===");
    println!("{}", serde_json::to_string_pretty(&level1_view)?);
    println!();

    Ok(())
}

fn sample_cap1_capsules() -> Vec<DecryptedCapsule> {
    [
        build_capsule(
            "cid:cap1-demo-001",
            "2024-09-23T08:30:00+00:00",
            "2024-09-23T09:00:00+00:00",
            "2024-09-23T10:05:00+00:00",
            json!({
                "category": "Blood Chemistry",
                "items": [
                    {
                        "name": "Blood Glucose",
                        "code": "GLU",
                        "value": 7.1,
                        "unit": "mmol/L",
                        "reference_range": { "min": 3.9, "max": 6.1 },
                        "status": "abnormal",
                        "flag": "high"
                    },
                    {
                        "name": "Total Cholesterol",
                        "code": "CHOL",
                        "value": 4.5,
                        "unit": "mmol/L",
                        "reference_range": { "min": 0.0, "max": 5.2 },
                        "status": "normal"
                    }
                ]
            }),
            Some(json!({
                "overall_status": "warning",
                "interpretation": "血糖偏高，需要关注饮食与运动。",
                "abnormal_count": 1,
                "critical_count": 0
            })),
        ),
        build_capsule(
            "cid:cap1-demo-002",
            "2024-10-05T07:45:00+00:00",
            "2024-10-05T08:30:00+00:00",
            "2024-10-05T09:10:00+00:00",
            json!({
                "category": "Liver Function",
                "items": [
                    {
                        "name": "ALT",
                        "code": "ALT",
                        "value": 65.0,
                        "unit": "U/L",
                        "reference_range": { "min": 7.0, "max": 40.0 },
                        "status": "abnormal",
                        "flag": "high"
                    },
                    {
                        "name": "AST",
                        "code": "AST",
                        "value": 58.0,
                        "unit": "U/L",
                        "reference_range": { "min": 13.0, "max": 35.0 },
                        "status": "abnormal",
                        "flag": "high"
                    }
                ]
            }),
            Some(json!({
                "overall_status": "warning",
                "interpretation": "肝功能指标偏高，需要复查并关注肝脏健康。",
                "abnormal_count": 2,
                "critical_count": 0
            })),
        ),
        build_capsule(
            "cid:cap1-demo-003",
            "2024-11-12T06:10:00+00:00",
            "2024-11-12T07:05:00+00:00",
            "2024-11-12T07:40:00+00:00",
            json!({
                "category": "Blood Pressure",
                "items": [
                    {
                        "name": "Systolic Blood Pressure",
                        "code": "SBP",
                        "value": 150,
                        "unit": "mmHg",
                        "reference_range": { "min": 90, "max": 120 },
                        "status": "critical",
                        "flag": "very_high"
                    },
                    {
                        "name": "Diastolic Blood Pressure",
                        "code": "DBP",
                        "value": 98,
                        "unit": "mmHg",
                        "reference_range": { "min": 60, "max": 80 },
                        "status": "critical",
                        "flag": "very_high"
                    }
                ]
            }),
            Some(json!({
                "overall_status": "critical",
                "interpretation": "血压显著升高，建议立即就医评估。",
                "abnormal_count": 0,
                "critical_count": 2
            })),
        ),
    ]
    .into_iter()
    .collect()
}

fn create_ollama_client() -> GatewayResult<LlmClient<OpenAiSdk>> {
    const BASE_URL: &str = "http://localhost:11434/v1";
    const MODEL_NAME: &str = "gpt-oss:20b";
    const API_KEY: &str = "";

    let sdk = OpenAiSdk::new(API_KEY, BASE_URL, MODEL_NAME)?;
    Ok(LlmClient::new(sdk))
}

fn build_capsule(
    capsule_id: &str,
    collected_at: &str,
    processed_at: &str,
    extracted_at: &str,
    test_category: serde_json::Value,
    summary: Option<serde_json::Value>,
) -> DecryptedCapsule {
    let meta = json!({
        "collector": { "name": "Central Hospital", "department": "Laboratory" },
        "owner": { "name": "Patient 001", "id": "P001" },
        "collection_info": {
            "collected_at": collected_at,
            "sample_type": "Blood"
        },
        "processing_info": {
            "processed_at": processed_at,
            "processor": "Dr. Li"
        },
        "sensitivity": { "level": "High", "encryption_required": true }
    });

    let tests = json!([test_category]);

    let bnf = json!({
        "tests": tests,
        "summary": summary.unwrap_or_else(|| json!({ "overall_status": "normal" })),
        "metadata": {
            "extracted_at": extracted_at,
            "extraction_version": "BNF-Medical-v1.2"
        }
    });

    DecryptedCapsule {
        capsule_id: capsule_id.to_string(),
        owner_id: "P001".into(),
        content_type: "medical.blood_test.interpretation".into(),
        created_at: chrono::DateTime::parse_from_rfc3339(collected_at)
            .map(|dt| dt.timestamp())
            .unwrap_or_default(),
        content: CapsuleContent::Cap1Content {
            cap0_id: format!("cid:cap0-source-{}", &capsule_id[4..]),
            meta_data: serde_json::to_vec(&meta).unwrap(),
            bnf_extract_data: serde_json::to_vec(&bnf).unwrap(),
        },
    }
}
