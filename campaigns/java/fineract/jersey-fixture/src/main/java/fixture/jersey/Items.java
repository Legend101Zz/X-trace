package fixture.jersey;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.container.AsyncResponse;
import jakarta.ws.rs.container.Suspended;
import jakarta.ws.rs.core.Context;
import java.util.concurrent.TimeUnit;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.StandardWatchEventKinds;
import java.nio.file.StandardOpenOption;

public class Items {
  @GET
  @Path("items/{id}")
  public String read(@PathParam("id") int id) {
    return id > 0 ? "found" : "other";
  }

  @GET
  @Path("lifecycle")
  public String lifecycle() throws Exception {
    // This private control directory is outside application data. Register before checking
    // the marker so a release between the check and wait cannot be lost.
    var control = java.nio.file.Path.of(System.getProperty("fixture.control"));
    long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(15);
    try (var watch = FileSystems.getDefault().newWatchService()) {
      control.register(watch, StandardWatchEventKinds.ENTRY_CREATE);
      Files.writeString(control.resolve("entered"), "", StandardOpenOption.CREATE_NEW);
      while (!Files.exists(control.resolve("release"))) {
        long remaining = deadline - System.nanoTime();
        if (remaining <= 0) throw new IllegalStateException("fixture barrier deadline");
        var key = watch.poll(remaining, TimeUnit.NANOSECONDS);
        if (key == null) throw new IllegalStateException("fixture barrier deadline");
        key.pollEvents();
        if (!key.reset()) throw new IllegalStateException("control directory disappeared");
      }
    }
    return "released";
  }

  @GET
  @Path("context")
  public String context(@Context HttpServletRequest request) {
    return request.getServletContext().getContextPath().equals(request.getContextPath())
        ? "same context path" : "different context path";
  }

  @POST
  @Path("items/{id}")
  public String convert(@PathParam("id") int id) {
    return Integer.toString(id);
  }

  @GET
  @Path("deferred")
  public void deferred(@Suspended AsyncResponse response) {
    response.setTimeoutHandler(pending -> pending.resume("resumed"));
    response.setTimeout(100, TimeUnit.MILLISECONDS);
  }
}
