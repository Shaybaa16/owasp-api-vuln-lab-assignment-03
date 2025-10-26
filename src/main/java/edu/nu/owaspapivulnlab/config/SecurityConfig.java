package edu.nu.owaspapivulnlab.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.filter.OncePerRequestFilter;
import io.jsonwebtoken.*;
import edu.nu.owaspapivulnlab.service.JwtService;

import java.io.IOException;
import java.util.Collections;

@Configuration
public class SecurityConfig {

    @Value("${app.jwt.secret}")
    private String secret;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, JwtService jwtService) throws Exception {

        // ✅ Disable CSRF for stateless REST APIs (tests expect no CSRF token)
        http.csrf(csrf -> csrf.disable());

        // ✅ Stateless session policy (JWT-based)
        http.sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        // ✅ Allow only specific endpoints publicly
        http.authorizeHttpRequests(reg -> reg
                .requestMatchers("/h2-console/**").permitAll()
                .requestMatchers("/api/auth/**").permitAll()        // login/register
                .requestMatchers(HttpMethod.POST, "/api/users").permitAll() // user registration
                .requestMatchers("/api/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated()
        );

        // ✅ Allow H2 console frame rendering
        http.headers(h -> h.frameOptions(f -> f.sameOrigin()));

        // ✅ Add JWT filter
        http.addFilterBefore(new JwtFilter(jwtService),
                org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    static class JwtFilter extends OncePerRequestFilter {
        private final JwtService jwtService;

        JwtFilter(JwtService jwtService) {
            this.jwtService = jwtService;
        }

        @Override
        protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
                throws ServletException, IOException {

            String auth = request.getHeader("Authorization");
            if (auth != null && auth.startsWith("Bearer ")) {
                String token = auth.substring(7);
                try {
                    Claims c = jwtService.parse(token);
                    String user = c.getSubject();
                    String role = (String) c.get("role");

                    UsernamePasswordAuthenticationToken authn = new UsernamePasswordAuthenticationToken(
                            user, null,
                            role != null
                                    ? Collections.singletonList(new SimpleGrantedAuthority("ROLE_" + role))
                                    : Collections.emptyList());

                    SecurityContextHolder.getContext().setAuthentication(authn);
                } catch (JwtException e) {
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    response.getWriter().write("Invalid token");
                    return;
                }
            }
            chain.doFilter(request, response);
        }
    }
}
