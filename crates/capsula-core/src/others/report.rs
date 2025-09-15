use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub identity: Value,
    pub summary: Value,
    pub full: Value,
}

impl Report {
    pub fn from_json(json: &Value) -> Self {
        Self {
            identity: json["identity"].clone(),
            summary: json["summary"].clone(),
            full: json["full"].clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn test_report_from_json() {
        // 构造一个示例 JSON
        let data = json!({
            "identity": {
                "report_id": "rep_20250908_0001",
                "version": "1.0",
                "producer": "某某医院体检中心",
                "created_at": "2025-09-08T10:00:00Z"
            },
            "summary": {
                "overall": "总体健康，无重大异常",
                "highlights": [
                    { "item": "血压", "status": "轻度偏高" }
                ],
                "recommendations": ["减少高盐饮食"]
            },
            "full": {
                "cbc": {
                    "WBC": "5.9",
                    "RBC": "4.72"
                }
            }
        });

        // 使用 from_json 构造 Report
        let report = Report::from_json(&data);

        // 基础断言
        assert_eq!(report.identity["report_id"], "rep_20250908_0001");
        assert_eq!(report.summary["overall"], "总体健康，无重大异常");
        assert_eq!(report.full["cbc"]["WBC"], "5.9");

        // 打印出来方便调试
        println!("{:#?}", report);
    }
}
