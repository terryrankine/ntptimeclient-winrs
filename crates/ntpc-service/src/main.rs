use std::process::ExitCode;

fn main() -> ExitCode {
    // Lossy is fine for the command words, which are ASCII. A `--config`
    // path with unpaired surrogates would be changed, so such a path is
    // simply not found and the run stops with a config error.
    let args: Vec<String> = std::env::args_os()
        .skip(1)
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    let code = ntpc_service::app::main_entry(&args, &mut std::io::stdout(), &mut std::io::stderr());
    ExitCode::from(code)
}
