package com.example.spring_security_6.repository;

import com.example.spring_security_6.token.Token;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;

public interface TokenRepository extends JpaRepository<Token, Long>
{
    @Query("SELECT t FROM tokens t JOIN users u ON (t.user.id = u.id) " +
            "WHERE u.id = :userId AND (t.expired = false OR t.revoked = false) ")
    List<Token> findAllValidTokensByUser(Long userId);

    Optional<Token> findByToken(String token);
}
