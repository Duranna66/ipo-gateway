package ru.ipo.ipogateway.security;

import lombok.AllArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtGrantedAuthoritiesConverterAdapter;
import org.springframework.security.web.server.SecurityWebFilterChain;

import java.util.Collection;

@Configuration
@RequiredArgsConstructor
@EnableWebFluxSecurity
public class SecurityConfig {
    private final CustomJwtConverter customJwtConverter;
    @Bean
    public SecurityWebFilterChain configureResourceServer(ServerHttpSecurity security) {
        return security.authorizeExchange()
                .pathMatchers("/actuator/health/**", "/*/*/*/public").permitAll()
                .pathMatchers("/*/*/*/moderator-access").hasAnyRole("Moderator", "Admin")
                .pathMatchers("/*/*/*/admin-access").hasRole("Admin")
                .anyExchange().authenticated()
                .and()
                .csrf().disable()
                .httpBasic().disable()
                .formLogin().disable()
                .logout().disable()
                .oauth2ResourceServer().jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter()))
                .and()
                .build();
    }
    @Bean
    public ReactiveJwtAuthenticationConverter jwtAuthenticationConverter() {
        var jwtAuthenticationConverter = new ReactiveJwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(
                new ReactiveJwtGrantedAuthoritiesConverterAdapter(customJwtConverter)
        );
        return jwtAuthenticationConverter;
    }
}
