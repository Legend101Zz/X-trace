package org.example.web;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

@Controller
@RequestMapping("/owners")
class OwnerController {

    @GetMapping("/{ownerId}")
    String show() {
        return "owners/show";
    }

    @PostMapping("/new")
    String create() {
        return "redirect:/owners";
    }

    @GetMapping
    String list() {
        return "owners/list";
    }

    @RequestMapping(value = "/search", method = RequestMethod.GET)
    String search() {
        return "owners/search";
    }

    @RequestMapping(path = {"/a", "/b"}, method = {RequestMethod.GET, RequestMethod.HEAD})
    String both() {
        return "owners/both";
    }

    static class Nested {
        String notAHandler() {
            return "x";
        }
    }
}
