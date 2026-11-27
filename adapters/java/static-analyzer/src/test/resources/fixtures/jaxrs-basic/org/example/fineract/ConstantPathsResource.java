package org.example.fineract;

import static jakarta.ws.rs.core.MediaType.APPLICATION_JSON;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;

@Path(ApiPaths.CLIENTS)
public class ConstantPathsResource {

    private static final String LOCAL = "/local";
    private static final String QUERY_KEY = "filter";

    @GET
    @Path(ApiPaths.SEARCH)
    @Consumes(APPLICATION_JSON)
    @Produces(ApiPaths.VND_JSON)
    public String search(@QueryParam(QUERY_KEY) final String filter) {
        return "[]";
    }

    @GET
    @Path(LOCAL + "/items")
    public String localItems() {
        return "[]";
    }

    @GET
    @Path(Elsewhere.MISSING)
    @Produces(Elsewhere.MISSING_MEDIA)
    public String missing() {
        return "";
    }

    @GET
    @Path("/dyn/" + System.getProperty("x"))
    public String dynamic() {
        return "";
    }
}
