package edu.nu.owaspapivulnlab.web;

import jakarta.validation.constraints.NotBlank;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;
import edu.nu.owaspapivulnlab.service.JwtService;
import org.springframework.security.crypto.password.PasswordEncoder;

// Add import
import edu.nu.owaspapivulnlab.service.RateLimitService;
import jakarta.servlet.http.HttpServletRequest;

// Add import for logging
import java.util.logging.Logger;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
    private static final Logger logger = Logger.getLogger(AuthController.class.getName());
    
    private final AppUserRepository users;
    private final JwtService jwt;
    private final PasswordEncoder passwordEncoder;
    private final RateLimitService rateLimitService;

    // Update constructor to include RateLimitService
    public AuthController(AppUserRepository users, JwtService jwt, PasswordEncoder passwordEncoder, RateLimitService rateLimitService) {
        this.users = users;
        this.jwt = jwt;
        this.passwordEncoder = passwordEncoder;
        this.rateLimitService = rateLimitService;
    }

    public static class LoginReq {
        @NotBlank
        private String username;
        @NotBlank
        private String password;

        public LoginReq() {}

        public LoginReq(String username, String password) {
            this.username = username;
            this.password = password;
        }

        public String username() { return username; }
        public String password() { return password; }

        public void setUsername(String username) { this.username = username; }
        public void setPassword(String password) { this.password = password; }
    }

    public static class TokenRes {
        private String token;

        public TokenRes() {}

        public TokenRes(String token) {
            this.token = token;
        }

        public String getToken() { return token; }
        public void setToken(String token) { this.token = token; }
    }

    // Add this method to AuthController class
    public static class RegisterReq {
        @NotBlank
        private String username;
        
        @NotBlank
        private String password;
        
        @NotBlank
        private String email;

        // SECURITY FIX: Remove role and isAdmin from registration - prevent mass assignment
        // Users should not be able to self-assign roles
        
        public RegisterReq() {}

        public RegisterReq(String username, String password, String email) {
            this.username = username;
            this.password = password;
            this.email = email;
        }

        // Getters and setters
        public String getUsername() { return username; }
        public void setUsername(String username) { this.username = username; }
        
        public String getPassword() { return password; }
        public void setPassword(String password) { this.password = password; }
        
        public String getEmail() { return email; }
        public void setEmail(String email) { this.email = email; }
    }

    // Update login method with rate limiting
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginReq req, HttpServletRequest request) {
        String clientIp = getClientIp(request);
        String rateLimitKey = "login_" + clientIp;
        
        if (!rateLimitService.allowRequest(rateLimitKey, "login")) {
            // SECURITY FIX: Log rate limit violations
            logger.warning("Rate limit exceeded for IP: " + clientIp + " - Username: " + req.username());
            
            Map<String, String> error = new HashMap<>();
            error.put("error", "Too many login attempts. Please try again in 1 minute.");
            return ResponseEntity.status(429).body(error); // 429 Too Many Requests
        }
        
        AppUser user = users.findByUsername(req.username()).orElse(null);
        if (user != null && passwordEncoder.matches(req.password(), user.getPassword())) {
            // SECURITY FIX: Log successful login
            logger.info("Successful login for user: " + req.username() + " from IP: " + clientIp);
            
            Map<String, Object> claims = new HashMap<>();
            claims.put("role", user.getRole());
            claims.put("isAdmin", user.isAdmin());
            String token = jwt.issue(user.getUsername(), claims);
            return ResponseEntity.ok(new TokenRes(token));
        }
        
        // SECURITY FIX: Log failed login attempts
        logger.warning("Failed login attempt for username: " + req.username() + " from IP: " + clientIp);
        
        Map<String, String> error = new HashMap<>();
        error.put("error", "invalid credentials");
        return ResponseEntity.status(401).body(error);
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterReq req, HttpServletRequest request) {
        String clientIp = getClientIp(request);
        
        if (users.findByUsername(req.getUsername()).isPresent()) {
            // SECURITY FIX: Log registration conflicts
            logger.warning("Registration conflict - username already exists: " + req.getUsername() + " from IP: " + clientIp);
            
            Map<String, String> error = new HashMap<>();
            error.put("error", "Username already exists");
            return ResponseEntity.status(409).body(error);
        }

        AppUser newUser = AppUser.builder()
                .username(req.getUsername())
                .password(passwordEncoder.encode(req.getPassword()))
                .email(req.getEmail())
                .role("USER")
                .isAdmin(false)
                .build();

        users.save(newUser);

        // SECURITY FIX: Log successful registrations
        logger.info("New user registered: " + req.getUsername() + " from IP: " + clientIp);

        Map<String, String> response = new HashMap<>();
        response.put("message", "User registered successfully");
        return ResponseEntity.status(201).body(response);
    }

    // SECURITY FIX: Helper method to get client IP address
    private String getClientIp(HttpServletRequest request) {
        String xfHeader = request.getHeader("X-Forwarded-For");
        if (xfHeader != null) {
            return xfHeader.split(",")[0];
        }
        return request.getRemoteAddr();
    }
}