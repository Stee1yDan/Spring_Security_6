package com.example.spring_security_6.demo;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/admin")
@PreAuthorize("hasRole('ADMIN')")
@RequiredArgsConstructor
public class AdminController
{
    @GetMapping
    @PreAuthorize("hasAuthority('admin:read')")
    public ResponseEntity<String> get()
    {
        return ResponseEntity.ok("GET:: Hello from admin");
    }

    @PostMapping
    @PreAuthorize("hasAuthority('admin:create')")
    public ResponseEntity<String> post()
    {
        return ResponseEntity.ok("POST:: Hello from admin");
    }

    @PutMapping
    @PreAuthorize("hasAuthority('admin:update')")
    public ResponseEntity<String> put()
    {
        return ResponseEntity.ok("PUT:: Hello from admin");
    }

    @DeleteMapping
    @PreAuthorize("hasAuthority('admin:delete')")
    public ResponseEntity<String> delete()
    {
        return ResponseEntity.ok("DELETE:: Hello from admin");
    }

}
