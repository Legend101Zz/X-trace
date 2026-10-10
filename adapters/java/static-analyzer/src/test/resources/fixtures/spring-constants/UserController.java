import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(Paths.API)
class UserController {

    private static final String LOCAL = "/local";

    @GetMapping(Paths.USERS)
    String users() {
        return "u";
    }

    @GetMapping(LOCAL + "/x")
    String local() {
        return "l";
    }

    @GetMapping("/lit" + Paths.API)
    String joined() {
        return "j";
    }

    @GetMapping(Elsewhere.MISSING)
    String missing() {
        return "m";
    }

    @GetMapping("/dyn/" + System.getProperty("x"))
    String dynamic() {
        return "d";
    }
}
