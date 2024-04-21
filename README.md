# Windows Service Runner

This repository contains `run-service`, a simple tool to run any command as a Windows service. The command is started in its own (console) process, and stopped with a Ctrl-C event on its console. The executable to invoke, its parameters, environment, and log files to redirect stdout/stderr into are configured with a JSON file passed to the runner as a command-line parameter.

## Similar tools
This runner is similar in purpose to other service managers like [NSSM](https://nssm.cc/), [Apache procrun](https://commons.apache.org/proper/commons-daemon/procrun.html), or [shawl](https://github.com/mtkennerly/shawl). In most cases, these tools will serve you just fine, and probably better than `run-service`. In some specific cases, `run-service` offers more convenience:
* Unlike procrun and NSSM, it's just a service runner, not a service manager. You do not need to invoke `run-service` to create or delete services. It does not create any additional files or registry entries to store configuration information - everything it needs is in the config file you supply to it. This makes `run-service` handy for installing services in MSI installers, as you do not need to use custom actions.
* Unlike shawl (which can also be used as a simple runner) `run-service` uses a JSON configuration file as the source of config information, and not the command line. This mostly eliminates the need to think about shell parsing logic (quotes, paths with spaces, etc.), and makes authoring services with a large amount of command-line arguments more elegant.

## How to Build
Install Rust via `rustup` and run `cargo build --release` in the root directory of the repository. You should find the binary under `target\release\run-service.exe`
The binary should be stand-alone, and should not require the VC++ redistributables to be installed.

## How to Use
Create a JSON file containing the configuration for your service:
```
{
	"executable_path": "path\\to\\test_srv.exe",
	"working_dir": "path\\to\\working\\directory",
	"arguments": ["--arg1", "arg2", "--arg3=val3"],
	"environment": { "ENV_KEY": "ENV_VALUE", "OTHER_ENV_KEY": "OTHER_ENV_VALUE" },
	"stdout_log_file": "path\\to\\stdout.log",
	"stderr_log_file": "path\\to\\stderr.log"
	"shutdown_grace_period_s": 30
}
```
All settings except `executable_path` are optional. If the `executable_path` or `working_dir` are relative paths, they are taken relative to the directory of the JSON config file - think of the service runner process itself running in the same directory as its config file.

The runner executable's command line is: `run-service.exe C:\path\to\config.json`. For example, you can create a service with the following command:
```
sc.exe create MyServiceName binpath="C:\path\to\run-service.exe C:\path\to\config.json"
```