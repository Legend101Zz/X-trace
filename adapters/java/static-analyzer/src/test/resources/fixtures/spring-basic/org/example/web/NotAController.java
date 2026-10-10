package org.example.web;

import org.springframework.web.bind.annotation.GetMapping;

/** Mapping annotations on a class that is not a Spring controller are not endpoints. */
interface NotAController {

    @GetMapping("/feign/only")
    String call();
}
