package edu.nu.owaspapivulnlab.web;

import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;

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

    // SECURITY FIX: Inject PasswordEncoder for password hashing
    public UserController(AppUserRepository users, PasswordEncoder passwordEncoder) {
        this.users = users;
        this.passwordEncoder = passwordEncoder;
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
        
        // SECURITY FIX: Return limited user data (will be improved with DTOs in next fix)
        Map<String, Object> response = new HashMap<>();
        response.put("id", user.getId());
        response.put("username", user.getUsername());
        response.put("email", user.getEmail());
        // SECURITY FIX: Do not expose password, role, or isAdmin to non-admin users
        
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
        
        // SECURITY FIX: Return limited user data
        Map<String, Object> response = new HashMap<>();
        response.put("id", currentUser.getId());
        response.put("username", currentUser.getUsername());
        response.put("email", currentUser.getEmail());
        
        return ResponseEntity.ok(response);
    }

    // SECURITY FIX: Prevent mass assignment and enforce default role
    @PostMapping
    public ResponseEntity<?> create(@Valid @RequestBody AppUser body) {
        // SECURITY FIX: Check if username already exists
        if (users.findByUsername(body.getUsername()).isPresent()) {
            Map<String, String> error = new HashMap<>();
            error.put("error", "Username already exists");
            return ResponseEntity.status(409).body(error);
        }

        // SECURITY FIX: Override role and isAdmin to prevent mass assignment
        body.setRole("USER");
        body.setAdmin(false);
        
        // SECURITY FIX: Hash password before saving
        body.setPassword(passwordEncoder.encode(body.getPassword()));
        
        AppUser savedUser = users.save(body);
        
        // SECURITY FIX: Return limited user data
        Map<String, Object> response = new HashMap<>();
        response.put("id", savedUser.getId());
        response.put("username", savedUser.getUsername());
        response.put("email", savedUser.getEmail());
        response.put("message", "User created successfully");
        
        return ResponseEntity.status(201).body(response);
    }

    // SECURITY FIX: Restrict user search to prevent enumeration
    @GetMapping("/search")
    public ResponseEntity<?> search(@RequestParam String q) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        
        // SECURITY FIX: Only allow search for authenticated users with minimum query length
        if (q == null || q.trim().length() < 2) {
            Map<String, String> error = new HashMap<>();
            error.put("error", "Search query must be at least 2 characters");
            return ResponseEntity.status(400).body(error);
        }
        
        List<AppUser> foundUsers = users.search(q.trim());
        
        // SECURITY FIX: Return limited user information
        List<Map<String, Object>> response = foundUsers.stream()
                .map(user -> {
                    Map<String, Object> userInfo = new HashMap<>();
                    userInfo.put("id", user.getId());
                    userInfo.put("username", user.getUsername());
                    // SECURITY FIX: Do not expose email in search results to prevent enumeration
                    return userInfo;
                })
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
}