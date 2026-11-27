package broken;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;

public class HealthyResource {

    @GET
    @Path("/healthy")
    public String healthy() {
        return "ok";
    }
}
