package com.example.spring_security_6.user;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Getter
public enum Permission
{
    ADMIN_READ("admin:read"),
    ADMIN_UPDATE("admin:read"),
    ADMIN_CREATE("admin:create"),
    ADMIN_DELETE("admin:delete"),

    MANAGER_READ("manager:read"),
    MANAGER_UPDATE("manager:read"),
    MANAGER_CREATE("manager:create"),
    MANAGER_DELETE("manager:delete");
    private final String permission;
}
