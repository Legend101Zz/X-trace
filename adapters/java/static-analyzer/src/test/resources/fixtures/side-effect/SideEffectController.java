import java.io.File;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/** Loading or running this class would create a marker file. Analyzing it must not. */
@RestController
class SideEffectController {

    static final Object TRIGGER = launch();

    static {
        launch();
    }

    static Object launch() {
        try {
            new File(System.getProperty("java.io.tmpdir"), "xtrace-static-analyzer-marker").createNewFile();
            Runtime.getRuntime().exec(new String[] {"touch", "xtrace-static-analyzer-process-marker"});
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
        return null;
    }

    @GetMapping("/side-effect")
    String get() {
        return "s";
    }
}
