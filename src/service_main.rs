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

/// Sum type wrapping errors that can happen during the service process's lifetime
#[derive(Debug)]
#[allow(dead_code)]
pub enum ServiceRuntimeError {
    Os(std::io::Error),
    Service(windows_service::Error),
	CouldNotKillChildProcess,
    Other(String),
}

/// To explain this: Internally, several threads are separately running:
/// - The thread handling commands from the Windows service manager;
/// - The thread watching the child process;
/// - Threads writing the stdout/stderr of the child process to log files;
/// - The "killer" thread, which is spawned when a stop is requested and counts up some time until the child process should be forcibly killed.
/// - The "service main" thread reporting the status of the service back to the Windows service manager.
/// Threads can send ControlMessages over an multi-producer-single-consumer channel to the "service main" thread.
/// The "service main" thread waits for messages on this channel and handles them accordingly.
enum ControlMessage {
	/// Notification: The child process exited. The "service main" thread will also exit.
    ChildProcessExited(u32),
	/// The Windows service manager requested this service to stop. The "service main" will report that a stop is pending, and send Ctrl-C to the child process.
	/// It will also start a "killer" thread, which will send KillRequested after the shutdown grace period has elapsed.
    StopRequested,
	/// The killer thread sends this after the shutdown grace period has passed. When receiving this, forcibly kill the child process and exit.
    KillRequested,
	/// The process watcher thread crashed. Forcibly kill the child process and exit.
    ProcessWatcherError,
}

/// Utility function to report the cstatus of the service. exit_code should be ServiceExitCode::Win32(0) unless the status is Stopped.
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

/// Separate threads for stdout and stderr run this function after the child process starts to dump the stdout/stderr streams of the child to log files.
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

// This is the function the child process watcher thread runs. It waits for the child process to exit and sends a ControlMessage with the exit code.
fn watch_child_process(mut child_process: Child, control_tx: mpsc::Sender<ControlMessage>) {
    let exit_code = match child_process.wait() {
        Ok(exit_status) => exit_status.code().unwrap_or(0),
        Err(_e) => {
            // If control_tx.send() below fails, the receiver closed already => the "service main" thread has exited and isn't waiting for us anymore.
            _ = control_tx.send(ControlMessage::ProcessWatcherError);
            return;
        }
    };

    _ = control_tx.send(ControlMessage::ChildProcessExited(exit_code as u32));
}

/// This function runs in the "main service" thread. It starts the child process, notifies the Windows service manager that the service has started, and starts waiting for ControlMessages
fn run_service_subprocess(
    _arguments: Vec<OsString>,
    status_handle: ServiceStatusHandle,
    config: ServiceConfig,
    config_location: &str,
    control_tx: mpsc::Sender<ControlMessage>,
    control_rx: mpsc::Receiver<ControlMessage>,
) -> Result<u32, ServiceRuntimeError> {
    // The service process's "current directory" is the parent directory of the config file
    // This is important in case the executable_path or working_dir paths are relative - then, they are relative to the location of the config file.
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

    let mut command = Command::new(config.executable_path);
    command.current_dir(working_dir).args(config.arguments).envs(config.environment).stdin(Stdio::null());
	
	// Set up piping for the stdout and stderr streams of the child process if needed
	if !config.stdout_log_file.is_none() {
		command.stdout(Stdio::piped());
	} else {
		command.stdout(Stdio::null());
	}
	if !config.stderr_log_file.is_none() {
		command.stderr(Stdio::piped());
	} else {
		command.stderr(Stdio::null());
	}
	
	// Report that the service has started BEFORE starting the child process, so that we have no error-exit points between starting the child process and the ControlMessage waiting loop.
	report_service_state(status_handle, ServiceState::Running, ServiceExitCode::Win32(0)).map_err(|e| ServiceRuntimeError::Service(e))?;
	
	// Start the child process
	let mut subproc = command.spawn().map_err(|e| ServiceRuntimeError::Os(e))?;
	
	// We keep a raw Windows HANDLE on the process, because a separate thread will wait on the Child and Child isn't cloneable.
	// This is safe on Windows, because PIDs don't get reused as long as a HANDLE on the process is open.
    let subproc_handle = HANDLE(subproc.as_raw_handle() as isize);
    
	// Start threads to pipe the stdout and stderr streams of the child process to logfiles if requested
    if let Some(stdout_log) = config.stdout_log_file {
		// We could also throw an error and exit if we wanted to log stdout but there is no stream, but this shouldn't really happen
		if let Some(stdout) = subproc.stdout.take() {
			std::thread::spawn(move || proxy_child_stream(stdout, &stdout_log));
		}
    }
    if let Some(stderr_log) = config.stderr_log_file {
		// We could also throw an error and exit if we wanted to log stderr but there is no stream, but this shouldn't really happen
		if let Some(stderr) = subproc.stderr.take() {
			std::thread::spawn(move || proxy_child_stream(stderr, &stderr_log));
		}
    }
	
	// Start child process watcher
    let control_tx_clone = control_tx.clone();
    std::thread::spawn(move || watch_child_process(subproc, control_tx_clone));

    // Set the service process to ignore Ctrl-C events sent on its console (we want to interrupt the child process, but not ourselves)
    // We set this here, after starting the child process, so the setting won't get inherited by the child process.
    unsafe {
        let _ = SetConsoleCtrlHandler(None, true); // TODO: Can we handle this error nicely?
    }

    loop {
		// See the docstrings on ControlMessage above
        match control_rx.recv() {
            Ok(ControlMessage::ChildProcessExited(exit_code)) => {
                // If we have a killer thread running at this point, it will continue running, but its KillRequested message will be ignored when it comes.
				return Ok(exit_code);
            }
            Ok(ControlMessage::StopRequested) => {
                // Send Ctrl-C event on our console (which we should ignore, but the child process will still get)
                unsafe {
                    _ = GenerateConsoleCtrlEvent(CTRL_C_EVENT, 0);
                }
                // Start the background killer thread
                let control_tx_clone = control_tx.clone();
                std::thread::spawn(move || {
                    std::thread::sleep(Duration::from_secs(config.shutdown_grace_period_s.into()));
                    _ = control_tx_clone.send(ControlMessage::KillRequested);
                });
                // Even if report_service_state returns an error here, we will ignore it.
				// We do not want to error out of this loop and miss the KillRequested signal, nor do we want to forcibly kill the child process unless we have no choice
                _ = report_service_state(
                    status_handle,
                    ServiceState::StopPending,
                    ServiceExitCode::Win32(0),
                );
            }
            Ok(ControlMessage::KillRequested) => {
                // Try to forcibly kill the child process. If this succeeds, wait for the process watcher to report the exit code.
                unsafe {
                    if let Err(_e) = TerminateProcess(subproc_handle, 1) {
						// If we cannot kill the child process, we can't do anything else - exit the loop with an error.
						return Err(ServiceRuntimeError::CouldNotKillChildProcess);
					}
                }
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
}

/// This function runs in the "service main" thread. It performs some setup, before calling run_service_subprocess where most of the run time will be spent.
fn run_service(arguments: Vec<OsString>) -> Result<(), ServiceRuntimeError> {
	// We pass the config in through mutable statics because there is no way to pass it as an argument (the signature of the function is fixed).
	// This should logically never fail, but just in case it does, we will crash before reporting the service has started at least.
    let config;
    let config_location;
    unsafe {
        config = SERVICE_CONFIG.take().unwrap();
        config_location = SERVICE_CONFIG_LOCATION.take().unwrap();
    }
	
	// Create the ControlMessage channel.
    let (control_tx, control_rx) = mpsc::channel();

	// This is the handler that passes Windows service manager requests to the "service main" thread.
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
	
	// Register the event handler
    // For "own-process" services Windows doesn't care about the service name in this call - this saves us the need to know our own service name.
    let status_handle = service_control_handler::register("", event_handler)
        .map_err(|e| ServiceRuntimeError::Service(e))?;
	
	// Report to the Windows service manager that we're starting up.
    report_service_state(
        status_handle,
        ServiceState::StartPending,
        ServiceExitCode::Win32(0),
    )
    .map_err(|e| ServiceRuntimeError::Service(e))?;
	
	// Now execute the inner run_service_subprocess routine, which will start the child process then wait for it to finish (or kill it, if it gets a ControlMessage to do that)
    match run_service_subprocess( arguments, status_handle, config, &config_location, control_tx, control_rx) {
		Ok(_exit_code) => {
			// The child process exited or was killed. Report the stop event then exit.
			report_service_state(
				status_handle,
				ServiceState::Stopped,
				ServiceExitCode::Win32(0),
			)
			.map_err(|e| ServiceRuntimeError::Service(e))?;
		}
		Err(_e) => {
			// The inner function exited with an error - usually this means that either the child process could not start, or a fatal error happened in the service runner itself (not the child process).
			// Report that we stopped with an error and exit.
			report_service_state(
				status_handle,
				ServiceState::Stopped,
				ServiceExitCode::Win32(1),
			)
			.map_err(|e| ServiceRuntimeError::Service(e))?;
		}
    }
	
    Ok(())
}

/// This is where the "service main" function starts.
/// It's only a thin wrapper around run_service in order to catch errors that occur before we have a handle to report service status over.
pub fn service_main(arguments: Vec<OsString>) {
    // Allocate a console if we don't already have one - otherwise we can't send Ctrl-C signals to children
    unsafe {
        _ = AllocConsole();
    }

    if let Err(_e) = run_service(arguments) {
        // An error happened before we could even open the handle to report the service status to. Exit.
    }
}
