use std::process::ExitCode;

fn main() -> ExitCode {
    // Lossy is fine: every accepted argument is ASCII, anything else is a
    // usage error anyway.
    let args: Vec<String> = std::env::args_os()
        .skip(1)
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    // Task 14 owns the full command line (run, service, status).
    let code = ntpc_service::cli::dispatch(&args, &mut std::io::stdout(), &mut std::io::stderr());
    ExitCode::from(code)
}
