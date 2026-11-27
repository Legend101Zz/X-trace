package org.example.fineract;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import retrofit2.http.GET;

public class NotAResource {
    public String plainMethod() {
        return "ok";
    }
}

@RestController
class SpringOnlyController {
    @GetMapping("/spring/ignored")
    String springOnly() {
        return "ignored";
    }
}

interface RetrofitClient {
    @GET("/retrofit/ignored")
    String call();
}

@jakarta.ws.rs.Path("/client/proxy")
@org.eclipse.microprofile.rest.client.inject.RegisterRestClient
interface MicroProfileClient {
    @jakarta.ws.rs.GET
    String callProxy();
}
