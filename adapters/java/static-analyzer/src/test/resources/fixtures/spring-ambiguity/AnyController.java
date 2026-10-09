import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
class AnyController {

    @RequestMapping("/any")
    String any() {
        return "ok";
    }
}
