package io.xtrace.attach;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.concurrent.TimeUnit;

/** Process double that proves the supervisor reports an unconfirmed kill without hiding context. */
final class UnstoppableProcess extends Process {
  private boolean destroyRequested;

  boolean destroyRequested() {
    return destroyRequested;
  }

  @Override
  public OutputStream getOutputStream() {
    return new ByteArrayOutputStream();
  }

  @Override
  public InputStream getInputStream() {
    return new ByteArrayInputStream(new byte[0]);
  }

  @Override
  public InputStream getErrorStream() {
    return new ByteArrayInputStream(new byte[0]);
  }

  @Override
  public int waitFor() {
    return 0;
  }

  @Override
  public boolean waitFor(long timeout, TimeUnit unit) {
    return false;
  }

  @Override
  public int exitValue() {
    throw new IllegalThreadStateException("test process remains alive");
  }

  @Override
  public void destroy() {
    destroyRequested = true;
  }

  @Override
  public Process destroyForcibly() {
    destroyRequested = true;
    return this;
  }

  @Override
  public boolean isAlive() {
    return true;
  }

  @Override
  public long pid() {
    return ProcessHandle.current().pid();
  }
}
