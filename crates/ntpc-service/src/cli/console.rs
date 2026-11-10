//! Console I/O for install: the yes or no question and plain lines.
//!
//! R83: interactive means stdin AND stderr are both consoles. The question
//! goes to stderr with a newline, so a wrapper that pipes stdout still shows
//! it, and a wrapper that pipes stderr makes the run non-interactive instead
//! of blocking on a question nobody sees. The answer read is bounded in
//! bytes (M11) and in time (R93): after [`ANSWER_TIMEOUT`] it counts as no.
//! Warnings go to stderr too, so redirecting stdout cannot hide them (N6).
//!
//! A deployment tool, a scheduled task or a hidden console must pass
//! `--silent` or `--confirm-domain-joined`. Then no question is asked.

#[cfg(windows)]
use std::io;
use std::io::{Read, Write};
use std::sync::mpsc;
use std::time::Duration;

#[cfg(windows)]
use super::Host;
#[cfg(windows)]
use ntpc_platform::JoinState;

/// Most bytes read for an answer. "yes" plus CR LF fits. A longer line is a
/// no, and nothing more is read.
pub const MAX_ANSWER_BYTES: usize = 16;

/// Reads one answer of at most [`MAX_ANSWER_BYTES`]. Stops at a newline, at
/// end of input or at the limit. Only `y` or `yes` (any case, surrounding
/// space ignored) is a yes. End of input, a read error and an overlong line
/// are a no.
pub fn read_answer(input: &mut impl Read) -> bool {
    let mut buf = Vec::with_capacity(MAX_ANSWER_BYTES);
    let mut byte = [0u8; 1];
    // One byte at a time: a console read returns a line, and asking for more
    // than one byte at a time could wait for input that never comes.
    loop {
        match input.read(&mut byte) {
            Ok(0) | Err(_) => break,
            Ok(_) if byte[0] == b'\n' => break,
            Ok(_) => {
                if buf.len() == MAX_ANSWER_BYTES {
                    return false;
                }
                buf.push(byte[0]);
            }
        }
    }
    let Ok(text) = std::str::from_utf8(&buf) else {
        return false;
    };
    matches!(text.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

/// How long the question waits for an answer (R93).
pub const ANSWER_TIMEOUT: Duration = Duration::from_secs(120);

/// The outcome of one bounded question.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer {
    /// `y` or `yes`.
    Yes,
    /// Anything else, end of input or a read error.
    No,
    /// Nothing arrived within the timeout.
    TimedOut,
}

/// Reads one answer on a helper thread and waits at most `timeout`. A
/// console read cannot be cancelled, so on timeout the helper is never
/// joined: it stays blocked and the process exits soon after.
pub fn read_answer_within<R: Read + Send + 'static>(input: R, timeout: Duration) -> Answer {
    let (tx, rx) = mpsc::channel();
    let spawned = std::thread::Builder::new()
        .name("answer".to_owned())
        .spawn(move || {
            let mut input = input;
            // The receiver may be gone after a timeout. Nothing to do then.
            let _ = tx.send(read_answer(&mut input));
        });
    if spawned.is_err() {
        // No thread, no way to bound the wait. Asking nothing is the safe no.
        return Answer::No;
    }
    match rx.recv_timeout(timeout) {
        Ok(true) => Answer::Yes,
        Ok(false) | Err(mpsc::RecvTimeoutError::Disconnected) => Answer::No,
        Err(mpsc::RecvTimeoutError::Timeout) => Answer::TimedOut,
    }
}

/// The console with its three streams and what kind each one is.
#[derive(Debug)]
pub struct Console<R, O, E> {
    /// Where answers come from. Taken by the first question.
    pub input: Option<R>,
    /// Plain lines.
    pub out: O,
    /// The question.
    pub err: E,
    /// stdin is a console.
    pub stdin_console: bool,
    /// stderr is a console.
    pub stderr_console: bool,
    /// How long a question waits. [`ANSWER_TIMEOUT`] in use, short in tests.
    pub answer_timeout: Duration,
}

impl<R: Read + Send + 'static, O: Write, E: Write> Console<R, O, E> {
    /// R83: both stdin and stderr must be consoles.
    #[must_use]
    pub const fn is_interactive(&self) -> bool {
        self.stdin_console && self.stderr_console
    }

    /// Writes the question to stderr with a newline, then reads a bounded
    /// answer within `answer_timeout`. Default no.
    pub fn ask_yes_no(&mut self, question: &str) -> bool {
        if writeln!(self.err, "{question} [y/N]")
            .and_then(|()| self.err.flush())
            .is_err()
        {
            // Nobody can see the question, so nobody can say yes.
            return false;
        }
        let Some(input) = self.input.take() else {
            return false;
        };
        match read_answer_within(input, self.answer_timeout) {
            Answer::Yes => true,
            Answer::No => false,
            Answer::TimedOut => {
                let _ = writeln!(
                    self.err,
                    "No answer within {} s. Counted as no.",
                    self.answer_timeout.as_secs()
                );
                false
            }
        }
    }

    /// One warning line to stderr, next to the question.
    pub fn warn(&mut self, line: &str) {
        let _ = writeln!(self.err, "{line}");
    }

    /// One plain line to stdout. A write error is ignored: there is nowhere
    /// else to report it, and the exit code still says what happened.
    pub fn say(&mut self, line: &str) {
        let _ = writeln!(self.out, "{line}");
    }
}

/// The real console host.
#[cfg(windows)]
pub type StdConsole = Console<io::Stdin, io::Stdout, io::Stderr>;

/// The real host: the process console plus the OS facts.
#[cfg(windows)]
#[derive(Debug)]
pub struct ConsoleHost(pub StdConsole);

#[cfg(windows)]
impl ConsoleHost {
    /// The process streams. Each one's console check is done once here.
    #[must_use]
    pub fn new() -> Self {
        use std::io::IsTerminal;
        Self(Console {
            stdin_console: io::stdin().is_terminal(),
            stderr_console: io::stderr().is_terminal(),
            input: Some(io::stdin()),
            out: io::stdout(),
            err: io::stderr(),
            answer_timeout: ANSWER_TIMEOUT,
        })
    }
}

#[cfg(windows)]
impl Default for ConsoleHost {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(windows)]
impl Host for ConsoleHost {
    fn is_elevated(&self) -> Result<bool, String> {
        ntpc_platform::is_elevated().map_err(|e| e.to_string())
    }
    fn join_state(&self) -> JoinState {
        ntpc_platform::join_state()
    }
    fn is_interactive(&self) -> bool {
        self.0.is_interactive()
    }
    fn ask_yes_no(&mut self, question: &str) -> bool {
        self.0.ask_yes_no(question)
    }
    fn say(&mut self, line: &str) {
        self.0.say(line);
    }
    fn warn(&mut self, line: &str) {
        self.0.warn(line);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{self, Cursor};

    fn console(
        input: &[u8],
        stdin: bool,
        stderr: bool,
    ) -> Console<Cursor<Vec<u8>>, Vec<u8>, Vec<u8>> {
        Console {
            input: Some(Cursor::new(input.to_vec())),
            out: Vec::new(),
            err: Vec::new(),
            stdin_console: stdin,
            stderr_console: stderr,
            answer_timeout: Duration::from_secs(5),
        }
    }

    #[test]
    fn interactive_needs_both_consoles() {
        assert!(console(b"", true, true).is_interactive());
        assert!(!console(b"", true, false).is_interactive());
        assert!(!console(b"", false, true).is_interactive());
        assert!(!console(b"", false, false).is_interactive());
    }

    #[test]
    fn the_question_goes_to_stderr_with_a_newline_and_not_stdout() {
        let mut c = console(b"y\n", true, true);
        assert!(c.ask_yes_no("Take over?"));
        assert_eq!(String::from_utf8(c.err).unwrap(), "Take over? [y/N]\n");
        assert_eq!(c.out, Vec::<u8>::new());
    }

    #[test]
    fn plain_lines_go_to_stdout() {
        let mut c = console(b"", true, true);
        c.say("hello");
        assert_eq!(c.out, b"hello\n");
        assert_eq!(c.err, Vec::<u8>::new());
    }

    #[test]
    fn answers() {
        for (input, yes) in [
            (&b"y\n"[..], true),
            (b"Y\r\n", true),
            (b"yes\r\n", true),
            (b"  YES  \n", true),
            (b"y", true),
            (b"n\n", false),
            (b"\n", false),
            (b"", false),
            (b"yess\n", false),
            (b"no\n", false),
            (b"\xff\n", false),
            (b"y\nyes\n", true),
            (b"x\ny\n", false),
        ] {
            assert_eq!(read_answer(&mut Cursor::new(input)), yes, "{input:?}");
        }
    }

    #[test]
    fn a_very_long_line_is_a_no_and_is_read_only_up_to_the_limit() {
        let mut long = vec![b'y'; 1 << 20];
        long.push(b'\n');
        let mut cur = Cursor::new(long);
        assert!(!read_answer(&mut cur));
        // At most the limit plus the byte that showed the line is too long.
        assert!(cur.position() <= MAX_ANSWER_BYTES as u64 + 1);
    }

    #[test]
    fn closed_stdin_is_a_no_without_waiting() {
        // `io::empty` is a closed stream: every read returns 0 at once.
        assert!(!read_answer(&mut io::empty()));
    }

    struct Failing;
    impl Read for Failing {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("broken"))
        }
    }

    #[test]
    fn a_read_error_is_a_no() {
        assert!(!read_answer(&mut Failing));
    }

    struct Broken;
    impl Write for Broken {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("closed"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn an_unwritable_stderr_is_a_no_even_with_yes_waiting() {
        let mut c = Console {
            input: Some(Cursor::new(b"y\n".to_vec())),
            out: Vec::new(),
            err: Broken,
            stdin_console: true,
            stderr_console: true,
            answer_timeout: Duration::from_secs(5),
        };
        assert!(!c.ask_yes_no("Take over?"));
    }

    /// Blocks until its sender is dropped, like a console nobody types into.
    struct Silent(mpsc::Receiver<()>);
    impl Read for Silent {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            let _ = self.0.recv();
            Ok(0)
        }
    }

    #[test]
    fn no_answer_within_the_timeout_is_a_no_and_says_so() {
        let (keep, rx) = mpsc::channel::<()>();
        let mut c = Console {
            input: Some(Silent(rx)),
            out: Vec::new(),
            err: Vec::new(),
            stdin_console: true,
            stderr_console: true,
            answer_timeout: Duration::from_millis(50),
        };
        let t0 = std::time::Instant::now();
        assert!(!c.ask_yes_no("Take over?"));
        assert!(t0.elapsed() < Duration::from_secs(5));
        let err = String::from_utf8(c.err).unwrap();
        assert!(err.contains("Counted as no"), "{err}");
        // The helper thread stays blocked until this sender goes.
        drop(keep);
    }

    #[test]
    fn read_answer_within_returns_the_answer_before_the_timeout() {
        let d = Duration::from_secs(5);
        assert_eq!(
            read_answer_within(Cursor::new(b"yes\n".to_vec()), d),
            Answer::Yes
        );
        assert_eq!(
            read_answer_within(Cursor::new(b"n\n".to_vec()), d),
            Answer::No
        );
        assert_eq!(read_answer_within(io::empty(), d), Answer::No);
    }

    #[test]
    fn the_default_timeout_is_120_seconds() {
        assert_eq!(ANSWER_TIMEOUT, Duration::from_secs(120));
    }

    #[test]
    fn a_second_question_has_no_input_and_is_a_no() {
        let mut c = console(b"y\n", true, true);
        assert!(c.ask_yes_no("first"));
        assert!(!c.ask_yes_no("second"));
    }

    #[test]
    fn warnings_go_to_stderr_with_the_question() {
        let mut c = console(b"", true, true);
        c.warn("domain joined");
        assert_eq!(c.err, b"domain joined\n");
        assert_eq!(c.out, Vec::<u8>::new());
    }
}
