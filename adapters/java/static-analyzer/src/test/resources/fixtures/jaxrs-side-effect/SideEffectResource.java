import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import java.io.File;

/** Loading or running this class would create a marker file. Analyzing it must not. */
@Path("/v1/side-effect")
class SideEffectResource {

    static final Object TRIGGER = launch();

    static {
        launch();
    }

    static Object launch() {
        try {
            new File(System.getProperty("java.io.tmpdir"), "xtrace-jaxrs-analyzer-marker").createNewFile();
            Runtime.getRuntime().exec(new String[] {"touch", "xtrace-jaxrs-analyzer-process-marker"});
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
        return null;
    }

    @GET
    String get() {
        return "s";
    }
}
