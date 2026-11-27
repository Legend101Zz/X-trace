package org.example.fineract;

import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;

@Path("/v1/offices")
@Consumes(MediaType.APPLICATION_JSON)
@Produces({ MediaType.APPLICATION_JSON, MediaType.TEXT_PLAIN })
public class OfficesApiResource {

    @GET
    public String retrieveOffices(@QueryParam("includeAllOffices") final boolean includeAll) {
        return "[]";
    }

    @GET
    @Path("{officeId}")
    @Produces("application/xml")
    public String retrieveOffice(
            @PathParam("officeId") final Long officeId,
            @HeaderParam("X-Correlation-Id") final String correlationId) {
        return "<office/>";
    }

    @PUT
    @Path("{officeId}")
    public String updateOffice(@PathParam("officeId") final Long officeId, final String body) {
        return "{}";
    }

    @javax.ws.rs.POST
    public String createOffice(final String body) {
        return "{}";
    }
}
