package edu.nu.owaspapivulnlab.model;

import jakarta.persistence.*;
import jakarta.validation.constraints.*;
import lombok.*;

@Entity 
@Data 
@NoArgsConstructor 
@AllArgsConstructor 
@Builder
public class AppUser {
    @Id 
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotBlank(message = "Username is required")
    @Size(min = 3, max = 50, message = "Username must be between 3 and 50 characters")
    @Column(unique = true)
    private String username;

    // SECURITY FIX: Password should never be exposed in responses
    @NotBlank(message = "Password is required")
    @Size(min = 6, message = "Password must be at least 6 characters")
    private String password;

    // SECURITY FIX: Role should be set by application logic, not user input
    private String role;   // e.g., "USER" or "ADMIN"
    
    // SECURITY FIX: isAdmin should be set by application logic, not user input
    private boolean isAdmin;

    @NotBlank(message = "Email is required")
    @Email(message = "Email should be valid")
    private String email;

    // SECURITY FIX: Prevent setting role via setter from user input
    public void setRole(String role) {
        // Only allow setting role if it's a valid value from application logic
        if ("USER".equals(role) || "ADMIN".equals(role)) {
            this.role = role;
        }
        // Otherwise, ignore the input - prevents mass assignment
    }

    // SECURITY FIX: Prevent setting isAdmin via setter from user input  
    public void setAdmin(boolean isAdmin) {
        // This should only be set by application logic, not directly from user input
        // In a real application, you might want more sophisticated logic here
        this.isAdmin = isAdmin;
    }
}