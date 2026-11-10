use std::process::ExitCode;

fn main() -> ExitCode {
    // Lossy is fine: every accepted argument is ASCII, anything else is a
    // usage error anyway.
    let args: Vec<String> = std::env::args_os()
        .skip(1)
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    // Minimal dispatch so install and uninstall are reachable. Task 14 owns
    // the full command line (run, service, status).
    match args.first().map(String::as_str) {
        Some("install") => ExitCode::from(ntpc_service::cli::run_install(&args[1..])),
        Some("uninstall") => ExitCode::from(ntpc_service::cli::run_uninstall(&args[1..])),
        _ => {
            println!(
                "{} (pre-alpha, no service logic yet)",
                ntpc_service::CRATE_NAME
            );
            ExitCode::SUCCESS
        }
    }
}
