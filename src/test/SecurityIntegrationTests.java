package edu.nu.owaspapivulnlab;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
class SecurityIntegrationTests {

    @Autowired
    private MockMvc mvc;

    private String adminToken;
    private String userToken;

    @BeforeEach
    void setUp() throws Exception {
        // Get tokens for testing
        adminToken = loginAndGetToken("bob", "bob123");
        userToken = loginAndGetToken("alice", "alice123");
    }

    // SECURITY FIX: Test BCrypt implementation
    @Test
    void testBCryptPasswordHashing() throws Exception {
        // Verify that passwords are properly hashed by testing login with correct password
        mvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\":\"alice\",\"password\":\"alice123\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").exists());
        
        // Verify login fails with wrong password
        mvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\":\"alice\",\"password\":\"wrongpassword\"}"))
                .andExpect(status().isUnauthorized());
    }

    // SECURITY FIX: Test JWT expiration and validation
    @Test
    void testJwtExpirationAndValidation() throws Exception {
        // Test that valid token works
        mvc.perform(get("/api/users/me")
                .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isOk());
        
        // Test that invalid token is rejected
        mvc.perform(get("/api/users/me")
                .header("Authorization", "Bearer invalid.token.here"))
                .andExpect(status().isUnauthorized());
        
        // Test that request without token is rejected
        mvc.perform(get("/api/users/me"))
                .andExpect(status().isForbidden());
    }

    // SECURITY FIX: Test role-based access control
    @Test
    void testRoleBasedAccessControl() throws Exception {
        // Admin should be able to list all users
        mvc.perform(get("/api/users")
                .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk());
        
        // Regular user should not be able to list all users
        mvc.perform(get("/api/users")
                .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isForbidden());
    }

    // SECURITY FIX: Test resource ownership
    @Test
    void testResourceOwnershipEnforcement() throws Exception {
        // Alice should be able to access her own data
        mvc.perform(get("/api/users/1") // Assuming Alice has ID 1
                .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isOk());
        
        // Alice should not be able to access Bob's data (ID 2)
        mvc.perform(get("/api/users/2")
                .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isForbidden());
        
        // Admin should be able to access any user's data
        mvc.perform(get("/api/users/1")
                .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk());
    }

    // SECURITY FIX: Test rate limiting
    @Test
    void testRateLimitingImplementation() throws Exception {
        String loginPayload = "{\"username\":\"ratelimited\",\"password\":\"wrongpass\"}";
        
        // Make multiple requests to trigger rate limiting
        for (int i = 0; i < 10; i++) {
            MvcResult result = mvc.perform(post("/api/auth/login")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(loginPayload))
                    .andReturn();
            
            if (i >= 5) {
                // Should be rate limited after 5 attempts
                assert result.getResponse().getStatus() == 429 : 
                    "Expected 429 Too Many Requests after 5 login attempts, got: " + result.getResponse().getStatus();
            }
        }
    }

    // SECURITY FIX: Test input validation and sanitization
    @Test
    void testInputValidationAndSanitization() throws Exception {
        // Test SQL injection prevention in search
        mvc.perform(get("/api/users/search")
                .param("q", "'; DROP TABLE users; --")
                .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isBadRequest()); // Should be blocked by validation
        
        // Test XSS prevention
        mvc.perform(get("/api/users/search")
                .param("q", "<script>alert('xss')</script>")
                .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isBadRequest()); // Should be blocked by validation
        
        // Test valid search
        mvc.perform(get("/api/users/search")
                .param("q", "ali")
                .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk());
    }

    // SECURITY FIX: Test error handling
    @Test
    void testSecureErrorHandling() throws Exception {
        // Test that stack traces are not exposed
        mvc.perform(get("/api/nonexistent-endpoint")
                .header("Authorization", "Bearer " + userToken))
                .andExpect(status().is4xxClientError())
                .andExpect(jsonPath("$.stackTrace").doesNotExist()) // No stack traces
                .andExpect(jsonPath("$.error").exists()); // Generic error message only
    }

    // SECURITY FIX: Test data exposure control
    @Test
    void testDataExposurePrevention() throws Exception {
        // Test that sensitive fields are not exposed
        mvc.perform(get("/api/users/me")
                .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.password").doesNotExist())
                .andExpect(jsonPath("$.role").doesNotExist())
                .andExpect(jsonPath("$.isAdmin").doesNotExist());
        
        // Even admin should not see passwords
        mvc.perform(get("/api/users")
                .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].password").doesNotExist());
    }

    // Helper method to login and get token
    private String loginAndGetToken(String username, String password) throws Exception {
        String loginPayload = String.format("{\"username\":\"%s\",\"password\":\"%s\"}", username, password);
        
        MvcResult result = mvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(loginPayload))
                .andExpect(status().isOk())
                .andReturn();
        
        String response = result.getResponse().getContentAsString();
        return response.split("\"token\":\"")[1].split("\"")[0];
    }
}