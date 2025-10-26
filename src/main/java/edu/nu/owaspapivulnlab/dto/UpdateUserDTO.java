package edu.nu.owaspapivulnlab.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Size;

public class UpdateUserDTO {
    
    @Size(min = 3, max = 50, message = "Username must be between 3 and 50 characters")
    private String username;
    
    @Size(min = 6, message = "Password must be at least 6 characters")
    private String password;
    
    @Email(message = "Email should be valid")
    private String email;
    
    // SECURITY FIX: No role or isAdmin fields - prevent privilege escalation
    
    // Default constructor
    public UpdateUserDTO() {}
    
    // Getters and setters
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
    
    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = password; }
    
    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }
}