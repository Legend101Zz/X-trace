package broken;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
class GoodController {

    @GetMapping("/good")
    String good() {
        return "g";
    }
}
