use std::ffi::OsString;
use std::fs::canonicalize;
use std::io::{Read, Write};
use std::os::windows::io::AsRawHandle;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use crate::config::ServiceConfig;
use crate::{SERVICE_CONFIG, SERVICE_CONFIG_LOCATION};

use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{
    self, ServiceControlHandlerResult, ServiceStatusHandle,
};

use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Console::{
    AllocConsole, GenerateConsoleCtrlEvent, SetConsoleCtrlHandler, CTRL_C_EVENT,
};
use windows::Win32::System::Threading::TerminateProcess;

#[derive(Debug)]
#[allow(dead_code)]
pub enum ServiceRuntimeError {
    Os(std::io::Error),
    Service(windows_service::Error),
    Other(String),
}

enum ControlMessage {
    ChildProcessExited(u32),
    StopRequested,
    KillRequested,
    ProcessWatcherError,
}

fn report_service_state(
    handle: ServiceStatusHandle,
    current_state: ServiceState,
    exit_code: ServiceExitCode,
) -> Result<(), windows_service::Error> {
    handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state,
        controls_accepted: ServiceControlAccept::STOP,
        exit_code,
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })
}

fn proxy_child_stream<T: Read>(mut stream: T, output_file_path: &str) {
    let mut log_file = std::fs::File::create(output_file_path).unwrap();
    let mut buf = [0u8; 1024];

    loop {
        let nbytes = stream.read(&mut buf).unwrap();
        if nbytes == 0 {
            break;
        }
        log_file.write(&buf[0..nbytes]).unwrap();
    }
}

fn watch_child_process(mut child_process: Child, control_tx: mpsc::Sender<ControlMessage>) {
    let exit_code = match child_process.wait() {
        Ok(exit_status) => exit_status.code().unwrap_or(0),
        Err(_e) => {
            // If control_tx.send fails, the receiver closed already => the "run_service_subprocess" thread has exited and isn't waiting for us anymore.
            _ = control_tx.send(ControlMessage::ProcessWatcherError);
            return;
        }
    };

    _ = control_tx.send(ControlMessage::ChildProcessExited(exit_code as u32));
}

fn run_service_subprocess(
    _arguments: Vec<OsString>,
    status_handle: ServiceStatusHandle,
    config: ServiceConfig,
    config_location: &str,
    control_tx: mpsc::Sender<ControlMessage>,
    control_rx: mpsc::Receiver<ControlMessage>,
) -> Result<(), ServiceRuntimeError> {
    // The service process's "current directory" is the parent directory of the config File
    // This might be useful if the executable or working paths are relative
    std::env::set_current_dir(
        canonicalize(config_location)
            .map_err(|e| ServiceRuntimeError::Os(e))?
            .parent()
            .ok_or(ServiceRuntimeError::Other(
                "Config location is equal to a filesystem root.".to_string(),
            ))?,
    )
    .map_err(|e| ServiceRuntimeError::Os(e))?;

    let working_dir = match config.working_dir {
        Some(s) => s,
        None => ".".to_string(),
    };

    let mut subproc = Command::new(config.executable_path)
        .current_dir(working_dir)
        .args(config.arguments)
        .envs(config.environment)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| ServiceRuntimeError::Os(e))?;

    let subproc_handle = HANDLE(subproc.as_raw_handle() as isize);
    let stdout = subproc.stdout.take().ok_or(ServiceRuntimeError::Other(
        "Child process stdout stream missing.".to_string(),
    ))?;
    let stderr = subproc.stderr.take().ok_or(ServiceRuntimeError::Other(
        "Child process stderr stream missing.".to_string(),
    ))?;

    if let Some(stdout_log) = config.stdout_log_file {
        std::thread::spawn(move || proxy_child_stream(stdout, &stdout_log));
    }
    if let Some(stderr_log) = config.stderr_log_file {
        std::thread::spawn(move || proxy_child_stream(stderr, &stderr_log));
    }
    let control_tx_clone = control_tx.clone();
    std::thread::spawn(move || watch_child_process(subproc, control_tx_clone));

    report_service_state(
        status_handle,
        ServiceState::Running,
        ServiceExitCode::Win32(0),
    )
    .map_err(|e| ServiceRuntimeError::Service(e))?;

    // Set the service process to ignore Ctrl-C events sent on its console (we want to interrupt the child process, but not ourselves)
    // We set this here, after starting the child process, so the setting won't get inherited
    unsafe {
        let _ = SetConsoleCtrlHandler(None, true);
    }

    loop {
        match control_rx.recv() {
            Ok(ControlMessage::ChildProcessExited(_code)) => {
                // Child process exited on its own -> exit the waiting loop. Any timers for kill requests will continue running, but we will not receive their requests anymore.
                break;
            }
            Ok(ControlMessage::StopRequested) => {
                // SCM wants us to stop the service -> Send a Ctrl-C event to the child process
                unsafe {
                    _ = GenerateConsoleCtrlEvent(CTRL_C_EVENT, 0);
                }
                // Set a background timer for shutdown_grace_period_s seconds which will request the child process to be killed when it finishes
                let control_tx_clone = control_tx.clone();
                std::thread::spawn(move || {
                    std::thread::sleep(Duration::from_secs(config.shutdown_grace_period_s.into()));
                    _ = control_tx_clone.send(ControlMessage::KillRequested);
                });
                // We will ignore errors when trying to report back to the SCM, because we don't want to exit the loop and miss the kill request
                _ = report_service_state(
                    status_handle,
                    ServiceState::StopPending,
                    ServiceExitCode::Win32(0),
                );
            }
            Ok(ControlMessage::KillRequested) => {
                // Requested subprocess to be killed, forcibly kill the child process and exit normally
                unsafe {
                    _ = TerminateProcess(subproc_handle, 1);
                }
                break;
            }
            Ok(ControlMessage::ProcessWatcherError) | Err(_) => {
                // The process watcher crashed, or there are no senders on the channel (which also means the process watcher crashed).
                // We can't recover from this, so just try to forcibly kill the child process and exit with an error
                unsafe {
                    _ = TerminateProcess(subproc_handle, 1);
                }
                return Err(ServiceRuntimeError::Other(
                    "Process watcher crashed".to_string(),
                ));
            }
        }
    }

    Ok(())
}

fn run_service(arguments: Vec<OsString>) -> Result<(), ServiceRuntimeError> {
    let config;
    let config_location;
    unsafe {
        config = SERVICE_CONFIG.take().unwrap();
        config_location = SERVICE_CONFIG_LOCATION.take().unwrap();
    }

    let (control_tx, control_rx) = mpsc::channel();

    let control_tx_clone = control_tx.clone();
    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop => {
                _ = control_tx_clone.send(ControlMessage::StopRequested);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };
    // For "own-process" services Windows doesn't care about the service name here - we do not need to know it.
    let status_handle = service_control_handler::register("", event_handler)
        .map_err(|e| ServiceRuntimeError::Service(e))?;
    report_service_state(
        status_handle,
        ServiceState::StartPending,
        ServiceExitCode::Win32(0),
    )
    .map_err(|e| ServiceRuntimeError::Service(e))?;

    if let Err(_e) = run_service_subprocess(
        arguments,
        status_handle,
        config,
        &config_location,
        control_tx,
        control_rx,
    ) {
        // rservrun errors/bugs that occurred during the service's run time are caught here.
        // Getting here usually means either a bad configuration or a bug in rservrun.
        report_service_state(
            status_handle,
            ServiceState::Stopped,
            ServiceExitCode::Win32(1),
        )
        .map_err(|e| ServiceRuntimeError::Service(e))?;
    } else {
        report_service_state(
            status_handle,
            ServiceState::Stopped,
            ServiceExitCode::Win32(0),
        )
        .map_err(|e| ServiceRuntimeError::Service(e))?;
    }

    Ok(())
}

pub fn service_main(arguments: Vec<OsString>) {
    // Allocate a console if we don't already have one - otherwise we can't send Ctrl+C signals to children
    unsafe {
        _ = AllocConsole();
    }

    if let Err(_e) = run_service(arguments) {
        // rservrun errors/bugs that occurred during the service's launch time are caught here.
        // Getting here usually means either a bad configuration or a bug in rservrun.
    }
}
