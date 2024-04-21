use std::collections::HashMap;
use std::io::Read;
use std::path::Path;

use serde::Deserialize;

#[derive(Debug)]
#[allow(dead_code)]
pub enum BadConfigError {
    ParsingError(serde_json::Error),
    Os(std::io::Error),
}

fn default_grace_period() -> u32 {
    return 60;
}

#[derive(Deserialize)]
pub struct ServiceConfig {
    pub executable_path: String,

    #[serde(default)]
    pub working_dir: Option<String>,

    #[serde(default)]
    pub arguments: Vec<String>,

    #[serde(default)]
    pub environment: HashMap<String, String>,

    #[serde(default)]
    pub stdout_log_file: Option<String>,

    #[serde(default)]
    pub stderr_log_file: Option<String>,

    #[serde(default = "default_grace_period")]
    pub shutdown_grace_period_s: u32,
}

pub fn load_config_file<T: AsRef<Path>>(path: T) -> Result<ServiceConfig, BadConfigError> {
    let mut config_json = String::new();
    let mut config_file = std::fs::File::open(path).map_err(|e| BadConfigError::Os(e))?;
    config_file
        .read_to_string(&mut config_json)
        .map_err(|e| BadConfigError::Os(e))?;

    serde_json::from_str(&config_json).map_err(|e| BadConfigError::ParsingError(e))
}
