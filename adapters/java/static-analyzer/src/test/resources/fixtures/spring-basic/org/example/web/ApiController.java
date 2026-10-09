package org.example.web;

import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(path = {"/api/v1", "/api/v2"})
public class ApiController {

    @PutMapping(value = "/pets/{petId}")
    public void update() {}

    @DeleteMapping(path = "/pets/{petId}")
    public void remove() {}
}
