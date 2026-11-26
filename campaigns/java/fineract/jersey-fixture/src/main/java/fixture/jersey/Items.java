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

public class Items {
  @GET
  @Path("items/{id}")
  public String read(@PathParam("id") int id) {
    return id > 0 ? "found" : "other";
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
