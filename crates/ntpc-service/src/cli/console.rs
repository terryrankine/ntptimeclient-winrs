//! Console I/O for install: the yes or no question and plain lines.
//!
//! R83: interactive means stdin AND stderr are both consoles. The question
//! goes to stderr with a newline, so a wrapper that pipes stdout still shows
//! it, and a wrapper that pipes stderr makes the run non-interactive instead
//! of blocking on a question nobody sees. The answer read is bounded (M11).

use std::io::{self, Read, Write};

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

/// The console with its three streams and what kind each one is.
#[derive(Debug)]
pub struct Console<R, O, E> {
    /// Where answers come from.
    pub input: R,
    /// Plain lines.
    pub out: O,
    /// The question.
    pub err: E,
    /// stdin is a console.
    pub stdin_console: bool,
    /// stderr is a console.
    pub stderr_console: bool,
}

impl<R: Read, O: Write, E: Write> Console<R, O, E> {
    /// R83: both stdin and stderr must be consoles.
    #[must_use]
    pub const fn is_interactive(&self) -> bool {
        self.stdin_console && self.stderr_console
    }

    /// Writes the question to stderr with a newline, then reads a bounded
    /// answer. Default no.
    pub fn ask_yes_no(&mut self, question: &str) -> bool {
        if writeln!(self.err, "{question} [y/N]")
            .and_then(|()| self.err.flush())
            .is_err()
        {
            // Nobody can see the question, so nobody can say yes.
            return false;
        }
        read_answer(&mut self.input)
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
            input: io::stdin(),
            out: io::stdout(),
            err: io::stderr(),
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn console(
        input: &[u8],
        stdin: bool,
        stderr: bool,
    ) -> Console<Cursor<Vec<u8>>, Vec<u8>, Vec<u8>> {
        Console {
            input: Cursor::new(input.to_vec()),
            out: Vec::new(),
            err: Vec::new(),
            stdin_console: stdin,
            stderr_console: stderr,
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
            input: Cursor::new(b"y\n".to_vec()),
            out: Vec::new(),
            err: Broken,
            stdin_console: true,
            stderr_console: true,
        };
        assert!(!c.ask_yes_no("Take over?"));
    }
}
