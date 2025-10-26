package edu.nu.owaspapivulnlab.web;

import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;

// Add imports
import edu.nu.owaspapivulnlab.dto.UserDTO;
import edu.nu.owaspapivulnlab.dto.CreateUserDTO;
import edu.nu.owaspapivulnlab.service.RateLimitService;
import jakarta.servlet.http.HttpServletRequest;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/users")
public class UserController {
    private final AppUserRepository users;
    private final PasswordEncoder passwordEncoder;
    private final RateLimitService rateLimitService;

    // Update constructor to include RateLimitService
    public UserController(AppUserRepository users, PasswordEncoder passwordEncoder, RateLimitService rateLimitService) {
        this.users = users;
        this.passwordEncoder = passwordEncoder;
        this.rateLimitService = rateLimitService;
    }

    // SECURITY FIX: Add ownership enforcement - users can only access their own data
    @GetMapping("/{id}")
    public ResponseEntity<?> get(@PathVariable Long id) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String currentUsername = auth.getName();
        
        Optional<AppUser> requestedUser = users.findById(id);
        
        if (requestedUser.isEmpty()) {
            Map<String, String> error = new HashMap<>();
            error.put("error", "User not found");
            return ResponseEntity.status(404).body(error);
        }
        
        AppUser user = requestedUser.get();
        
        // SECURITY FIX: Check if current user is accessing their own data or is admin
        if (!user.getUsername().equals(currentUsername) && !isAdmin(auth)) {
            Map<String, String> error = new HashMap<>();
            error.put("error", "Access denied");
            return ResponseEntity.status(403).body(error);
        }
        
        // SECURITY FIX: Return UserDTO instead of raw entity
        UserDTO response = new UserDTO(user.getId(), user.getUsername(), user.getEmail());
        return ResponseEntity.ok(response);
    }

    // SECURITY FIX: Add endpoint for users to get their own profile
    @GetMapping("/me")
    public ResponseEntity<?> getCurrentUser() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String currentUsername = auth.getName();
        
        Optional<AppUser> user = users.findByUsername(currentUsername);
        
        if (user.isEmpty()) {
            Map<String, String> error = new HashMap<>();
            error.put("error", "User not found");
            return ResponseEntity.status(404).body(error);
        }
        
        AppUser currentUser = user.get();
        
        // SECURITY FIX: Return UserDTO instead of raw entity
        UserDTO response = new UserDTO(currentUser.getId(), currentUser.getUsername(), currentUser.getEmail());
        return ResponseEntity.ok(response);
    }

    // SECURITY FIX: Prevent mass assignment and enforce default role
    @PostMapping
    public ResponseEntity<?> create(@Valid @RequestBody CreateUserDTO createUserDTO) {
        // SECURITY FIX: Check if username already exists
        if (users.findByUsername(createUserDTO.getUsername()).isPresent()) {
            Map<String, String> error = new HashMap<>();
            error.put("error", "Username already exists");
            return ResponseEntity.status(409).body(error);
        }

        // SECURITY FIX: Create user from DTO - prevents mass assignment
        AppUser newUser = AppUser.builder()
                .username(createUserDTO.getUsername())
                .password(passwordEncoder.encode(createUserDTO.getPassword()))
                .email(createUserDTO.getEmail())
                .role("USER") // Default role - cannot be set by user
                .isAdmin(false) // Default to non-admin - cannot be set by user
                .build();

        AppUser savedUser = users.save(newUser);
        
        // SECURITY FIX: Return UserDTO instead of raw entity
        UserDTO response = new UserDTO(savedUser.getId(), savedUser.getUsername(), savedUser.getEmail());
        
        Map<String, Object> finalResponse = new HashMap<>();
        finalResponse.put("user", response);
        finalResponse.put("message", "User created successfully");
        
        return ResponseEntity.status(201).body(finalResponse);
    }

    // SECURITY FIX: Restrict user search to prevent enumeration
    @GetMapping("/search")
    public ResponseEntity<?> search(@RequestParam String q, HttpServletRequest request) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        
        // SECURITY FIX: Apply rate limiting to search
        String clientIp = getClientIp(request);
        String currentUsername = auth.getName();
        String rateLimitKey = "search_" + currentUsername + "_" + clientIp;
        
        if (!rateLimitService.allowRequest(rateLimitKey, "search")) {
            Map<String, String> error = new HashMap<>();
            error.put("error", "Too many search requests. Please try again in 1 minute.");
            return ResponseEntity.status(429).body(error);
        }
        
        // SECURITY FIX: Only allow search for authenticated users with minimum query length
        if (q == null || q.trim().length() < 2) {
            Map<String, String> error = new HashMap<>();
            error.put("error", "Search query must be at least 2 characters");
            return ResponseEntity.status(400).body(error);
        }
        
        List<AppUser> foundUsers = users.search(q.trim());
        
        // SECURITY FIX: Return UserDTO instead of raw entities
        List<UserDTO> response = foundUsers.stream()
                .map(user -> new UserDTO(user.getId(), user.getUsername(), null)) // Don't expose email in search
                .collect(Collectors.toList());
        
        return ResponseEntity.ok(response);
    }

    // SECURITY FIX: Restrict user listing to admins only with limited data
    @GetMapping
    public ResponseEntity<?> list() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        
        // SECURITY FIX: Only allow admins to list all users
        if (!isAdmin(auth)) {
            Map<String, String> error = new HashMap<>();
            error.put("error", "Access denied");
            return ResponseEntity.status(403).body(error);
        }
        
        List<AppUser> allUsers = users.findAll();
        
        // SECURITY FIX: Return limited user information even for admins
        List<Map<String, Object>> response = allUsers.stream()
                .map(user -> {
                    Map<String, Object> userInfo = new HashMap<>();
                    userInfo.put("id", user.getId());
                    userInfo.put("username", user.getUsername());
                    userInfo.put("email", user.getEmail());
                    userInfo.put("role", user.getRole());
                    userInfo.put("isAdmin", user.isAdmin());
                    // SECURITY FIX: Never expose passwords
                    return userInfo;
                })
                .collect(Collectors.toList());
        
        return ResponseEntity.ok(response);
    }

    // SECURITY FIX: Restrict deletion to own account or admin privileges
    @DeleteMapping("/{id}")
    public ResponseEntity<?> delete(@PathVariable Long id) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String currentUsername = auth.getName();
        
        Optional<AppUser> userToDelete = users.findById(id);
        if (userToDelete.isEmpty()) {
            Map<String, String> error = new HashMap<>();
            error.put("error", "User not found");
            return ResponseEntity.status(404).body(error);
        }
        
        AppUser user = userToDelete.get();
        
        // SECURITY FIX: Users can only delete their own account, admins can delete any account
        if (!user.getUsername().equals(currentUsername) && !isAdmin(auth)) {
            Map<String, String> error = new HashMap<>();
            error.put("error", "Access denied");
            return ResponseEntity.status(403).body(error);
        }
        
        users.deleteById(id);
        
        Map<String, String> response = new HashMap<>();
        response.put("status", "deleted");
        return ResponseEntity.ok(response);
    }

    // SECURITY FIX: Helper method to check if user is admin
    private boolean isAdmin(Authentication auth) {
        return auth.getAuthorities().stream()
                .anyMatch(grantedAuthority -> grantedAuthority.getAuthority().equals("ROLE_ADMIN"));
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