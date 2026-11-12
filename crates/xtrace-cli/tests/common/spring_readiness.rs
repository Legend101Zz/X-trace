use std::io::{self, Read};
use std::process::Child;
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

const STDERR_LIMIT: usize = 4096;
const STDERR_DRAIN_GRACE: Duration = Duration::from_millis(250);

#[derive(Default)]
pub(super) struct ReadinessStderr {
    state: Arc<StderrState>,
    // Lets the regressions synchronize with the diagnostic wait.
    wait_started: Option<Sender<Instant>>,
}

#[derive(Default)]
struct StderrState {
    sample: Mutex<StderrSample>,
    drained: Condvar,
}

#[derive(Default)]
struct StderrSample {
    tail: Vec<u8>,
    truncated: bool,
    active_readers: usize,
}

impl ReadinessStderr {
    // Keep a bounded snapshot available while the existing reader drains or scans the full stream.
    pub(super) fn observe<R: Read>(&self, reader: R) -> StderrReader<R> {
        self.state.sample.lock().expect("readiness stderr snapshot").active_readers += 1;
        StderrReader { reader, state: Arc::clone(&self.state) }
    }

    fn wait_for_drain(&self, deadline: Instant) {
        let sample = self.state.sample.lock().expect("readiness stderr snapshot");
        let now = Instant::now();
        if sample.active_readers == 0 || now >= deadline {
            return;
        }
        // A descendant may keep stderr open after stdout closes.
        let until = deadline.min(now + STDERR_DRAIN_GRACE);
        if let Some(wait_started) = &self.wait_started {
            let _ = wait_started.send(until);
        }
        let remaining = until.saturating_duration_since(Instant::now());
        let _result = self
            .state
            .drained
            .wait_timeout_while(sample, remaining, |sample| sample.active_readers != 0)
            .expect("readiness stderr snapshot");
    }

    fn summary(&self) -> String {
        let sample = self.state.sample.lock().expect("readiness stderr snapshot");
        // Direct CI runs can print panic messages. Emit only fixed diagnostics, even if the
        // matching stderr line includes a path, option value, or other fixture data.
        let diagnostics: Vec<_> = [
            "Error: Unable to access jarfile",
            "Could not find or load main class",
            "UnsupportedClassVersionError",
            "Unrecognized VM option",
            "Could not create the Java Virtual Machine",
            "java.net.BindException",
            "XTR-CLI-DAEMON-LOCKED",
            "XTR-RUN-INVALID-LAUNCH",
            "XTR-JAVA-AGENT-UNAVAILABLE",
            "XTR-JAVA-INSTRUMENTATION",
        ]
        .into_iter()
        .filter(|diagnostic| {
            sample.tail.windows(diagnostic.len()).any(|bytes| bytes == diagnostic.as_bytes())
        })
        .collect();
        let detail = if diagnostics.is_empty() {
            "no recognized startup diagnostics".to_owned()
        } else {
            diagnostics.join(", ")
        };
        let truncated = if sample.truncated { ", truncated to tail" } else { "" };
        format!("stderr ({} bytes sampled{truncated}): {detail}", sample.tail.len())
    }
}

pub(super) struct StderrReader<R> {
    reader: R,
    state: Arc<StderrState>,
}

impl<R: Read> Read for StderrReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let count = self.reader.read(buf)?;
        if count != 0 {
            let mut sample = self.state.sample.lock().expect("readiness stderr snapshot");
            let keep = count.min(STDERR_LIMIT);
            let evict = sample.tail.len().saturating_sub(STDERR_LIMIT - keep);
            sample.truncated |= evict != 0 || keep < count;
            sample.tail.drain(..evict);
            sample.tail.extend_from_slice(&buf[count - keep..count]);
        }
        Ok(count)
    }
}

impl<R> Drop for StderrReader<R> {
    fn drop(&mut self) {
        self.state.sample.lock().expect("readiness stderr snapshot").active_readers -= 1;
        self.state.drained.notify_all();
    }
}

#[track_caller]
pub(super) fn wait_for_fixture(
    lines: &Receiver<Vec<u8>>,
    deadline: Instant,
    child: &mut Child,
    stderr: &ReadinessStderr,
) -> u16 {
    match receive_bound_port(lines, deadline) {
        Ok(port) => port,
        Err(error) => {
            if error == RecvTimeoutError::Disconnected {
                stderr.wait_for_drain(deadline);
            }
            panic!("{}", failure_message(error, child, stderr));
        }
    }
}

fn receive_bound_port(
    lines: &Receiver<Vec<u8>>,
    deadline: Instant,
) -> Result<u16, RecvTimeoutError> {
    loop {
        let remaining =
            deadline.checked_duration_since(Instant::now()).ok_or(RecvTimeoutError::Timeout)?;
        let line = lines.recv_timeout(remaining)?;
        // Boot 4.1.1 logs the connector's local port only after it has started.
        let line = String::from_utf8_lossy(&line);
        if let Some((_, address)) = line.split_once("Tomcat started on port ") {
            if let Some((port, _)) = address.split_once(" (http)") {
                let port = port.parse::<u16>().expect("Spring fixture bound port");
                assert_ne!(port, 0, "Spring fixture must report its actual bound port");
                return Ok(port);
            }
        }
    }
}

fn failure_message(error: RecvTimeoutError, child: &mut Child, stderr: &ReadinessStderr) -> String {
    let reason = match error {
        RecvTimeoutError::Timeout => "Spring fixture timed out waiting for its bound port",
        RecvTimeoutError::Disconnected => {
            "Spring fixture stdout disconnected before its bound port"
        }
    };
    // EOF can precede process exit, so report whichever status is available now.
    let status = match child.try_wait() {
        Ok(Some(status)) => status.to_string(),
        Ok(None) => "no exit status available yet".to_owned(),
        Err(error) => format!("status check failed ({:?})", error.kind()),
    };
    format!("{reason}; child status: {status}; {}", stderr.summary())
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead, BufReader, Cursor};
    use std::panic::{self, AssertUnwindSafe};
    use std::process::{Command, Stdio};
    use std::sync::mpsc;
    use std::thread;

    use super::*;

    const FAILING_SCRIPT: &str =
        "printf '%s\\n' 'Error: Unable to access jarfile PRIVATE_FIXTURE_VALUE' >&2; exit 23";
    const READER_WATCHDOG: Duration = Duration::from_secs(5);

    #[test]
    fn spring_readiness_distinguishes_disconnect_and_timeout() {
        let (sender, receiver) = mpsc::channel();
        let deadline = Instant::now() + Duration::from_secs(45);
        sender.send(b"Tomcat initialized with port 0 (http)".to_vec()).unwrap();
        sender.send(b"Tomcat started on port 47129 (http) with context path '/'".to_vec()).unwrap();
        drop(sender);
        assert_eq!(receive_bound_port(&receiver, deadline), Ok(47129));
        assert_eq!(receive_bound_port(&receiver, deadline), Err(RecvTimeoutError::Disconnected));

        let (_sender, receiver) = mpsc::channel();
        assert_eq!(receive_bound_port(&receiver, Instant::now()), Err(RecvTimeoutError::Timeout));
    }

    #[test]
    fn spring_readiness_reports_exit_status_and_stderr() {
        let mut child = Command::new("sh")
            .args(["-c", FAILING_SCRIPT])
            .stderr(Stdio::piped())
            .spawn()
            .expect("start failing child");
        let pipe = child.stderr.take().expect("child stderr");
        let prefix = vec![b'x'; STDERR_LIMIT * 2];
        let stderr = ReadinessStderr::default();
        let mut drained = Vec::new();
        stderr.observe(Cursor::new(prefix).chain(pipe)).read_to_end(&mut drained).unwrap();
        let status = child.wait().expect("reap failing child");
        assert_eq!(status.code(), Some(23));
        assert!(drained.ends_with(b"PRIVATE_FIXTURE_VALUE\n"));

        let disconnected = failure_message(RecvTimeoutError::Disconnected, &mut child, &stderr);
        let timed_out = failure_message(RecvTimeoutError::Timeout, &mut child, &stderr);
        assert!(disconnected.contains("stdout disconnected"));
        assert!(timed_out.contains("timed out"));
        for message in [disconnected, timed_out] {
            assert!(message.contains(&format!("child status: {status}")));
            assert!(message.contains("stderr (4096 bytes sampled, truncated to tail)"));
            assert!(message.contains("Error: Unable to access jarfile"));
            assert!(!message.contains("PRIVATE_FIXTURE_VALUE"));
        }
    }

    #[test]
    fn spring_readiness_samples_stderr_after_stdout_disconnects() {
        let mut child = Command::new("sh")
            .args(["-c", FAILING_SCRIPT])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start failing child");
        let lines = read_stdout_lines(&mut child);
        let (wait_started, wait) = mpsc::channel();
        let stderr = ReadinessStderr { wait_started: Some(wait_started), ..Default::default() };
        let mut pipe = stderr.observe(child.stderr.take().expect("child stderr"));
        let drainer = thread::spawn(move || {
            // Leave the bytes in the pipe until stdout disconnect triggers diagnostic sampling.
            let until = wait.recv();
            let mut drained = Vec::new();
            pipe.read_to_end(&mut drained).unwrap();
            (until, drained)
        });

        let deadline = Instant::now() + READER_WATCHDOG;
        let message = readiness_failure(&lines, deadline, &mut child, &stderr);
        drop(stderr);
        let (until, drained) = drainer.join().unwrap();
        assert_eq!(child.wait().unwrap().code(), Some(23));
        assert!(until.unwrap() < deadline);
        assert!(drained.ends_with(b"PRIVATE_FIXTURE_VALUE\n"));
        assert!(message.contains("stdout disconnected"));
        assert!(message.contains("Error: Unable to access jarfile"));
        assert!(!message.contains("PRIVATE_FIXTURE_VALUE"));
    }

    #[test]
    fn spring_readiness_respects_deadline_with_inherited_stderr() {
        // The replacement shell inherits stderr on fd 3 and keeps it open until stdin closes.
        let mut child = Command::new("sh")
            .args(["-c", "exec sh -c 'read -r release; printf x >&3' 3>&2 2>&- 1>&-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start child with inherited stderr");
        let stdin = child.stdin.take().expect("child stdin");
        let lines = read_stdout_lines(&mut child);
        let (wait_started, wait) = mpsc::channel();
        let stderr = ReadinessStderr { wait_started: Some(wait_started), ..Default::default() };
        let mut pipe = stderr.observe(child.stderr.take().expect("child stderr"));
        let drainer = thread::spawn(move || {
            let mut drained = Vec::new();
            pipe.read_to_end(&mut drained).unwrap();
            drained
        });

        let (reported, report) = mpsc::channel();
        let waiter = thread::spawn(move || {
            let stdout_end = lines.recv_timeout(READER_WATCHDOG);
            let deadline = Instant::now() + STDERR_DRAIN_GRACE / 2;
            let message = readiness_failure(&lines, deadline, &mut child, &stderr);
            let _ = reported.send((stdout_end, deadline, message));
            child.wait().unwrap()
        });
        let result = report.recv_timeout(READER_WATCHDOG);
        // Release the inherited descriptor even if readiness failed to report in time.
        drop(stdin);
        assert!(waiter.join().unwrap().success());
        assert_eq!(drainer.join().unwrap(), b"x");
        let (stdout_end, deadline, message) = result.expect("report while stderr is still open");
        assert_eq!(stdout_end, Err(RecvTimeoutError::Disconnected));
        assert_eq!(wait.try_recv(), Ok(deadline));
        assert!(message.contains("stdout disconnected"));
        assert!(message.contains("no recognized startup diagnostics"));
    }

    fn read_stdout_lines(child: &mut Child) -> Receiver<Vec<u8>> {
        let stdout = child.stdout.take().expect("child stdout");
        let (sender, lines) = mpsc::channel();
        thread::spawn(move || {
            for line in BufReader::new(stdout).split(b'\n') {
                let _ = sender.send(line.expect("read child stdout"));
            }
        });
        lines
    }

    fn readiness_failure(
        lines: &Receiver<Vec<u8>>,
        deadline: Instant,
        child: &mut Child,
        stderr: &ReadinessStderr,
    ) -> String {
        let panic = panic::catch_unwind(AssertUnwindSafe(|| {
            wait_for_fixture(lines, deadline, child, stderr)
        }))
        .expect_err("readiness must fail");
        *panic.downcast::<String>().expect("readiness failure message")
    }
}
