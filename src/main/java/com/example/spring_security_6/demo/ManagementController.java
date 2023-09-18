package com.example.spring_security_6.demo;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/manager")
@RequiredArgsConstructor
public class ManagementController
{
    @GetMapping
    public ResponseEntity<String> get()
    {
        return ResponseEntity.ok("GET:: Hello from manager");
    }

    @PostMapping
    public ResponseEntity<String> post()
    {
        return ResponseEntity.ok("POST:: Hello from manager");
    }

    @PutMapping
    public ResponseEntity<String> put()
    {
        return ResponseEntity.ok("PUT:: Hello from manager");
    }

}
