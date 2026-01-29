//! Unpacking result structure for JSON output

use serde::{Serialize, Deserialize};
use std::path::PathBuf;

/// Result of an unpacking operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnpackResult {
    /// Whether unpacking succeeded
    pub success: bool,
    
    /// Whether OEP was found
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oep_found: Option<bool>,
    
    /// OEP address if found
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oep_address: Option<String>,
    
    /// Detected Themida version
    #[serde(skip_serializing_if = "Option::is_none")]
    pub themida_version: Option<String>,
    
    /// Number of instructions executed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instructions_executed: Option<u64>,
    
    /// APIs that were called
    #[serde(skip_serializing_if = "Option::is_none")]
    pub apis_called: Option<Vec<String>>,
    
    /// Output file path
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<String>,
    
    /// Error message if failed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    
    /// Warnings encountered
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warnings: Option<Vec<String>>,
    
    /// Code sections that were decrypted
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_sections_modified: Option<Vec<String>>,
    
    /// Whether emulation hit timeout
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_reached: Option<bool>,
}

impl UnpackResult {
    /// Create a successful result
    pub fn success(
        oep: Option<u64>,
        version: String,
        instructions: u64,
        output: PathBuf,
    ) -> Self {
        Self {
            success: true,
            oep_found: Some(oep.is_some()),
            oep_address: oep.map(|addr| format!("0x{:x}", addr)),
            themida_version: Some(version),
            instructions_executed: Some(instructions),
            apis_called: None,
            output: Some(output.display().to_string()),
            error: None,
            warnings: None,
            code_sections_modified: None,
            timeout_reached: None,
        }
    }
    
    /// Create a failure result
    pub fn failure(error: String, version: Option<String>) -> Self {
        Self {
            success: false,
            oep_found: Some(false),
            oep_address: None,
            themida_version: version,
            instructions_executed: None,
            apis_called: None,
            output: None,
            error: Some(error),
            warnings: None,
            code_sections_modified: None,
            timeout_reached: None,
        }
    }
    
    /// Add warnings
    pub fn with_warnings(mut self, warnings: Vec<String>) -> Self {
        self.warnings = Some(warnings);
        self
    }
    
    /// Add API call list
    pub fn with_apis(mut self, apis: Vec<String>) -> Self {
        self.apis_called = Some(apis);
        self
    }
    
    /// Mark as timeout
    pub fn with_timeout(mut self) -> Self {
        self.timeout_reached = Some(true);
        self
    }
    
    /// Convert to JSON string
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}
