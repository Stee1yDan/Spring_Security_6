package com.example.spring_security_6.config;

import com.example.spring_security_6.user.Permission;
import com.example.spring_security_6.user.Role;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig
{
    private final JwtAuthFilter authFilter;
    private final AuthenticationProvider authenticationProvider;
    private final LogoutHandler logoutHandler;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception
    {
        http
                .csrf()
                .disable()
                .authorizeHttpRequests()
                .requestMatchers("/api/v1/auth/**")
                    .permitAll()

                .requestMatchers("/api/v1/management/**")
                    .hasAnyRole(Role.ADMIN.name(), Role.MANAGER.name())
                .requestMatchers(HttpMethod.GET,"/api/v1/management/**")
                    .hasAnyAuthority(Permission.ADMIN_READ.name(),Permission.MANAGER_READ.name())
                .requestMatchers(HttpMethod.POST,"/api/v1/management/**")
                    .hasAnyAuthority(Permission.ADMIN_CREATE.name(),Permission.MANAGER_CREATE.name())
                .requestMatchers(HttpMethod.PUT,"/api/v1/management/**")
                    .hasAnyAuthority(Permission.ADMIN_UPDATE.name(),Permission.MANAGER_UPDATE.name())
                .requestMatchers(HttpMethod.DELETE,"/api/v1/management/**")
                    .hasAnyAuthority(Permission.ADMIN_DELETE.name(),Permission.MANAGER_DELETE.name())

//                .requestMatchers("/api/v1/admin/**")
//                    .hasRole(Role.ADMIN.name())
//                .requestMatchers(HttpMethod.GET,"/api/v1/admin/**")
//                    .hasAuthority(Permission.ADMIN_READ.name())
//                .requestMatchers(HttpMethod.POST,"/api/v1/admin/**")
//                    .hasAuthority(Permission.ADMIN_CREATE.name())
//                .requestMatchers(HttpMethod.PUT,"/api/v1/admin/**")
//                    .hasAuthority(Permission.ADMIN_UPDATE.name())
//                .requestMatchers(HttpMethod.DELETE,"/api/v1/admin/**")
//                    .hasAuthority(Permission.ADMIN_DELETE.name())

                .anyRequest()
                .authenticated()

                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authenticationProvider(authenticationProvider)
                .addFilterBefore(authFilter, UsernamePasswordAuthenticationFilter.class)
                .logout()
                .logoutUrl("/api/v1/auth/logout")
                .addLogoutHandler(logoutHandler)
                .logoutSuccessHandler((request, response, authentication) -> SecurityContextHolder.clearContext());

        return http.build();
    }
}
