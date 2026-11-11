//! Bounded fixture children with private, capped output and no pipe-reader threads.

use std::fs::File;
use std::io::{self, Read as _, Seek as _};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::time::{Duration, Instant};

const OUTPUT_LIMIT: u64 = 4096;
const CLEANUP_BUDGET: Duration = Duration::from_millis(100);

fn wait_until(child: &mut Child, deadline: Instant) -> io::Result<Option<ExitStatus>> {
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Some(status));
        }
        if Instant::now() >= deadline {
            return Ok(None);
        }
        std::thread::yield_now();
    }
}

fn captured(mut file: File) -> io::Result<Vec<u8>> {
    file.rewind()?;
    let mut bytes = Vec::new();
    file.take(OUTPUT_LIMIT + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > OUTPUT_LIMIT {
        return Err(io::Error::other("fixture output exceeded its cap"));
    }
    Ok(bytes)
}

pub(crate) fn output(command: &mut Command) -> io::Result<Output> {
    output_until(command, Instant::now() + crate::probe::ADMISSION_BUDGET)
}

fn output_until(command: &mut Command, deadline: Instant) -> io::Result<Output> {
    let stdout = tempfile::tempfile()?;
    let stderr = tempfile::tempfile()?;
    let mut child = command
        .stdin(Stdio::null())
        .stdout(stdout.try_clone()?)
        .stderr(stderr.try_clone()?)
        .spawn()?;
    let status = match wait_until(&mut child, deadline) {
        Ok(Some(status)) => status,
        failure => {
            // Signal only this owned child. Neither waiting for exit nor draining inherited
            // pipes may turn a failed fixture into a lane-wide hang.
            let _ = child.kill();
            if wait_until(&mut child, Instant::now() + CLEANUP_BUDGET)?.is_none() {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "fixture child cleanup is unconfirmed",
                ));
            }
            return Err(match failure {
                Err(error) => error,
                _ => io::Error::new(io::ErrorKind::TimedOut, "fixture child exceeded its deadline"),
            });
        }
    };
    Ok(Output { status, stdout: captured(stdout)?, stderr: captured(stderr)? })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_output_captures_both_streams_and_a_failed_exit() -> io::Result<()> {
        let output = output(
            Command::new("/bin/sh")
                .args(["-c", "printf fixture-out; printf fixture-err >&2; exit 7"]),
        )?;
        assert_eq!(output.status.code(), Some(7));
        assert_eq!(output.stdout, b"fixture-out");
        assert_eq!(output.stderr, b"fixture-err");
        Ok(())
    }

    #[test]
    fn an_expired_fixture_is_killed_and_reaped() {
        let result = output_until(Command::new("/bin/sleep").arg("60"), Instant::now());
        assert!(matches!(
            result,
            Err(error) if error.kind() == io::ErrorKind::TimedOut
                && error.to_string() == "fixture child exceeded its deadline"
        ));
    }
}
