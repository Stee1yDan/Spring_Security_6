package com.example.spring_security_6.token;

import com.example.spring_security_6.user.User;
import jakarta.persistence.*;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.SuperBuilder;

@Entity(name = "tokens")
@Data
@SuperBuilder
@AllArgsConstructor
@NoArgsConstructor
public class Token
{
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @NotEmpty
    private String token;

    @Enumerated(EnumType.STRING)
    private TokenType tokenType;

    @NotNull
    @Column(nullable = false)
    private boolean expired;

    @NotNull
    @Column(nullable = false)
    private boolean revoked;

    @ManyToOne
    @JoinColumn(name = "user_id")
    private User user;
}
