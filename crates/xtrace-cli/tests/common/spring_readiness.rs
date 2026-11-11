use std::io::{self, Read};
use std::process::Child;
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::time::Instant;

const STDERR_LIMIT: usize = 4096;

#[derive(Default)]
pub(super) struct ReadinessStderr(Arc<Mutex<StderrSample>>);

#[derive(Default)]
struct StderrSample {
    tail: Vec<u8>,
    truncated: bool,
}

impl ReadinessStderr {
    // Keep a bounded snapshot available while the existing reader drains or scans the full stream.
    pub(super) fn observe<R: Read>(&self, reader: R) -> StderrReader<R> {
        StderrReader { reader, sample: Arc::clone(&self.0) }
    }

    fn summary(&self) -> String {
        let sample = self.0.lock().expect("readiness stderr snapshot");
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
    sample: Arc<Mutex<StderrSample>>,
}

impl<R: Read> Read for StderrReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let count = self.reader.read(buf)?;
        if count != 0 {
            let mut sample = self.sample.lock().expect("readiness stderr snapshot");
            let keep = count.min(STDERR_LIMIT);
            let evict = sample.tail.len().saturating_sub(STDERR_LIMIT - keep);
            sample.truncated |= evict != 0 || keep < count;
            sample.tail.drain(..evict);
            sample.tail.extend_from_slice(&buf[count - keep..count]);
        }
        Ok(count)
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
        Err(error) => panic!("{}", failure_message(error, child, stderr)),
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
    // EOF can precede process exit. Sample what is available without waiting on either pipe.
    let status = match child.try_wait() {
        Ok(Some(status)) => status.to_string(),
        Ok(None) => "no exit status available yet".to_owned(),
        Err(error) => format!("status check failed ({:?})", error.kind()),
    };
    format!("{reason}; child status: {status}; {}", stderr.summary())
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::process::{Command, Stdio};
    use std::sync::mpsc;
    use std::time::Duration;

    use super::*;

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
            .args([
                "-c",
                "printf '%s\\n' 'Error: Unable to access jarfile PRIVATE_FIXTURE_VALUE' >&2; exit 23",
            ])
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
}
