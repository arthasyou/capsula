use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recipe {
    /// Source IDs to fetch data from
    pub ids: Vec<String>,

    /// Start timestamp (Unix time)
    pub from: i64,

    /// End timestamp (Unix time)
    pub to: i64,

    /// Privacy level (e.g., "L1", "L2", "L3", "L4")
    pub privacy: String,

    /// Aggregation mode ("llm" or "rule")
    pub aggregate: String,

    /// LLM input prompt (optional, for LLM-based aggregation)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub llm_input: Option<String>,
}
