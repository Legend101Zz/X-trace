package fixture.jersey;

import jakarta.ws.rs.Path;

@Path("groups")
public class Groups {
  @Path("{group}")
  public Items items() {
    return new Items();
  }
}
