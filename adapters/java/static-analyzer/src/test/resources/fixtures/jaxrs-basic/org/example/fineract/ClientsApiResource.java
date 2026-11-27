package org.example.fineract;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.CookieParam;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.DefaultValue;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.HEAD;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.OPTIONS;
import jakarta.ws.rs.PATCH;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.UriInfo;

@Path("/v1/clients")
public class ClientsApiResource {

    @GET
    @Consumes({ MediaType.APPLICATION_JSON })
    @Produces({ MediaType.APPLICATION_JSON })
    public String retrieveAll(
            @Context final UriInfo uriInfo,
            @QueryParam("sqlSearch") final String sqlSearch,
            @DefaultValue("0") @QueryParam("offset") final Integer offset,
            @HeaderParam("Fineract-Platform-TenantId") final String tenantId,
            @CookieParam("JSESSIONID") final String sessionId) {
        return "[]";
    }

    @GET
    @Path("{clientId}")
    @Consumes({ MediaType.APPLICATION_JSON })
    @Produces({ MediaType.APPLICATION_JSON })
    public String retrieveOne(@PathParam("clientId") final Long clientId) {
        return "{}";
    }

    @GET
    @Path("{clientId:\\d+}/accounts")
    @Produces({ MediaType.APPLICATION_JSON })
    public String retrieveAccounts(@PathParam("clientId") final Long clientId) {
        return "{}";
    }

    @POST
    @Consumes({ MediaType.APPLICATION_JSON })
    @Produces({ MediaType.APPLICATION_JSON })
    public String create(final String apiRequestBodyAsJson) {
        return "{}";
    }

    @PUT
    @Path("{clientId}")
    @Consumes({ MediaType.APPLICATION_JSON })
    @Produces({ MediaType.APPLICATION_JSON })
    public String update(@PathParam("clientId") final Long clientId, final String body) {
        return "{}";
    }

    @PATCH
    @Path("{clientId}")
    @Consumes({ MediaType.APPLICATION_JSON })
    @Produces({ MediaType.APPLICATION_JSON })
    public String patch(@PathParam("clientId") final Long clientId, final String body) {
        return "{}";
    }

    @DELETE
    @Path("{clientId}")
    @Produces({ MediaType.APPLICATION_JSON })
    public String delete(@PathParam("clientId") final Long clientId) {
        return "{}";
    }

    @HEAD
    @Path("health")
    public void health() {}

    @OPTIONS
    public void options() {}

    @POST
    @Path("form")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.TEXT_PLAIN)
    public String submitForm(@FormParam("displayName") final String displayName) {
        return displayName;
    }

    @Path("{clientId}/notes")
    public Object notesSubResource(@PathParam("clientId") final Long clientId) {
        return new Object();
    }

    static class NestedHelper {
        String helperMethod() {
            return "not-an-endpoint";
        }
    }
}
