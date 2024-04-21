mod config;
mod service_main;

use crate::config::{load_config_file, BadConfigError, ServiceConfig};
use crate::service_main::service_main;

use windows_service::{define_windows_service, service_dispatcher};

// We had to pass those args through statics because there's no other way to pass the args to the service main function...
pub static mut SERVICE_CONFIG: Option<ServiceConfig> = None;
pub static mut SERVICE_CONFIG_LOCATION: Option<String> = None;

define_windows_service!(ffi_service_main, service_main);

#[derive(Debug)]
#[allow(dead_code)]
pub enum LaunchServiceError {
    BadArguments(String),
    ServiceDispatchError(windows_service::Error),
    BadConfig(BadConfigError),
    Os(std::io::Error),
}

fn launch_service() -> Result<(), LaunchServiceError> {
    let arguments: Vec<String> = std::env::args().collect();
    if arguments.len() != 2 {
        return Err(LaunchServiceError::BadArguments(format!("Invalid command-line arguments. Correct format: rservrun.exe <path to config JSON file>")));
    }
    let config = load_config_file(&arguments[1]).map_err(|e| LaunchServiceError::BadConfig(e))?;

    unsafe {
        SERVICE_CONFIG = Some(config);
        SERVICE_CONFIG_LOCATION = Some(arguments[1].to_string());
    }

    service_dispatcher::start("", ffi_service_main)
        .map_err(|e| LaunchServiceError::ServiceDispatchError(e))?;
    Ok(())
}

fn main() {
    if let Err(_e) = launch_service() {
        // rservrun errors/bugs that occurred during service startup are caught here.
        // Getting here usually means either a bad configuration or a bug in rservrun.
    }
}
