package com.example.spring_seecurity_6.repository;

import com.example.spring_seecurity_6.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User,Long>
{
    Optional<User> findByEmail(String email);
}
