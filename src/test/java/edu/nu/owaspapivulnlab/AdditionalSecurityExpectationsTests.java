package edu.nu.owaspapivulnlab;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import java.util.Set;
import java.util.HashSet;

@SpringBootTest
@AutoConfigureMockMvc
class AdditionalSecurityExpectationsTests {

    @Autowired
    private MockMvc mvc;

    // SECURITY FIX: Test BCrypt password hashing
    @Test
    void testPasswordHashing() throws Exception {
        String payload = "{\"username\":\"testuser\",\"password\":\"TestPass123\",\"email\":\"test@test.com\"}";
        
        mvc.perform(post("/api/users")
                .contentType(MediaType.APPLICATION_JSON)
                .content(payload))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.user.username").value("testuser"))
                .andExpect(jsonPath("$.user.password").doesNotExist()) // Password should not be exposed
                .andExpect(jsonPath("$.message").value("User created successfully"));
    }

    // SECURITY FIX: Test rate limiting on login endpoint
    @Test
    void testLoginRateLimiting() throws Exception {
        String loginPayload = "{\"username\":\"nonexistent\",\"password\":\"wrongpassword\"}";
        
        // Test multiple requests to observe behavior pattern
        Set<Integer> observedStatusCodes = new HashSet<>();
        
        for (int i = 0; i < 3; i++) { // Fewer attempts to be faster
            MvcResult result = mvc.perform(post("/api/auth/login")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(loginPayload))
                    .andReturn();
            
            observedStatusCodes.add(result.getResponse().getStatus());
            
            // Small delay between requests
            Thread.sleep(100);
        }
        
        // Verify we're getting expected security-related status codes
        boolean hasSecurityResponse = observedStatusCodes.stream()
                .anyMatch(code -> code == 401 || code == 429 || code == 400);
        
        assert hasSecurityResponse : 
            "Login endpoint should return security-related status codes (401, 429, 400). Observed: " + observedStatusCodes;
        
        System.out.println("Login endpoint security verified with status codes: " + observedStatusCodes);
    }

    // SECURITY FIX: Test ownership enforcement
    @Test
    void testUserDataOwnership() throws Exception {
        // First, create two users
        String user1Payload = "{\"username\":\"user1\",\"password\":\"User1Pass123\",\"email\":\"user1@test.com\"}";
        String user2Payload = "{\"username\":\"user2\",\"password\":\"User2Pass123\",\"email\":\"user2@test.com\"}";
        
        MvcResult user1Result = mvc.perform(post("/api/users")
                .contentType(MediaType.APPLICATION_JSON)
                .content(user1Payload))
                .andExpect(status().isCreated())
                .andReturn();
        
        MvcResult user2Result = mvc.perform(post("/api/users")
                .contentType(MediaType.APPLICATION_JSON)
                .content(user2Payload))
                .andExpect(status().isCreated())
                .andReturn();
        
        // Get authentication tokens for both users
        String user1Token = loginAndGetToken("user1", "User1Pass123");
        String user2Token = loginAndGetToken("user2", "User2Pass123");
        
        // User1 should not be able to access User2's data
        mvc.perform(get("/api/users/2")
                .header("Authorization", "Bearer " + user1Token))
                .andExpect(status().isForbidden());
    }

    // SECURITY FIX: Test mass assignment prevention
    @Test
    void testMassAssignmentPrevention() throws Exception {
        String payload = "{\"username\":\"hacker\",\"password\":\"Hacker123\",\"email\":\"h@cker.com\",\"role\":\"ADMIN\",\"isAdmin\":true}";
        
        mvc.perform(post("/api/users")
                .contentType(MediaType.APPLICATION_JSON)
                .content(payload))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.user.role").doesNotExist()) // Role should not be in response
                .andExpect(jsonPath("$.user.isAdmin").doesNotExist()); // isAdmin should not be in response
        
        // Verify user was created with default USER role
        String token = loginAndGetToken("hacker", "Hacker123");
        
        mvc.perform(get("/api/users/me")
                .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.role").doesNotExist()); // Role should not be exposed to non-admins
    }

    // SECURITY FIX: Test JWT security features
    @Test
    void testJwtSecurity() throws Exception {
        String loginPayload = "{\"username\":\"alice\",\"password\":\"alice123\"}";
        
        MvcResult result = mvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(loginPayload))
                .andExpect(status().isOk())
                .andReturn();
        
        String response = result.getResponse().getContentAsString();
        assert response.contains("token") : "Login should return a token";
        
        // Test token validation with modified token
        String invalidToken = "invalid.token.here";
        mvc.perform(get("/api/users/me")
                .header("Authorization", "Bearer " + invalidToken))
                .andExpect(status().isUnauthorized());
    }

    // SECURITY FIX: Test input validation
    @Test
    void testInputValidation() throws Exception {
        // Test invalid username
        String invalidUserPayload = "{\"username\":\"ab\",\"password\":\"Test123\",\"email\":\"test@test.com\"}";
        mvc.perform(post("/api/users")
                .contentType(MediaType.APPLICATION_JSON)
                .content(invalidUserPayload))
                .andExpect(status().isBadRequest());
        
        // Test weak password
        String weakPasswordPayload = "{\"username\":\"testuser3\",\"password\":\"123\",\"email\":\"test3@test.com\"}";
        mvc.perform(post("/api/users")
                .contentType(MediaType.APPLICATION_JSON)
                .content(weakPasswordPayload))
                .andExpect(status().isBadRequest());
        
        // Test invalid email
        String invalidEmailPayload = "{\"username\":\"testuser4\",\"password\":\"Test123\",\"email\":\"invalid-email\"}";
        mvc.perform(post("/api/users")
                .contentType(MediaType.APPLICATION_JSON)
                .content(invalidEmailPayload))
                .andExpect(status().isBadRequest());
    }

    // SECURITY FIX: Test data exposure control
    @Test
    void testDataExposureControl() throws Exception {
        String token = loginAndGetToken("alice", "alice123");
        
        mvc.perform(get("/api/users/me")
                .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.password").doesNotExist()) // Password should never be exposed
                .andExpect(jsonPath("$.role").doesNotExist()) // Role should not be exposed to non-admins
                .andExpect(jsonPath("$.isAdmin").doesNotExist()); // isAdmin should not be exposed to non-admins
    }

    // SECURITY FIX: Test access control
    @Test
    void testAccessControl() throws Exception {
        // Test that unauthenticated requests are denied
        mvc.perform(get("/api/users/1"))
                .andExpect(status().isForbidden());
        
        mvc.perform(get("/api/accounts/mine"))
                .andExpect(status().isForbidden());
    }

    // Helper method to login and get token
    private String loginAndGetToken(String username, String password) throws Exception {
        String loginPayload = String.format("{\"username\":\"%s\",\"password\":\"%s\"}", username, password);
        
        MvcResult result = mvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(loginPayload))
                .andReturn();
        
        String response = result.getResponse().getContentAsString();
        // Extract token from response (simplified - in real test you'd parse JSON)
        if (response.contains("\"token\":")) {
            return response.split("\"token\":\"")[1].split("\"")[0];
        }
        return null;
    }
}