# Identified Vulnerabilities and Fixes - Assignment 03
## Secure Software Design - Fall 2025

### Executive Summary
This document outlines the security vulnerabilities identified in the OWASP API Vulnerability Lab and the corresponding fixes implemented to address each vulnerability. The application has been secured against OWASP API Security Top 10 vulnerabilities.

---

## GitHub Repository
**URL**: https://github.com/Shaybaa16/owasp-api-vuln-lab-assignment-03

### Branch Structure
- **vulnerable-code**: Original vulnerable codebase (initial commit)
- **fixed-code**: Secure implementation with all 10 security fixes

### Pull Request
**PR**: https://github.com/Shaybaa16/owasp-api-vuln-lab-assignment-03/pull/new/fixed-code
(Base: vulnerable-code ← Compare: fixed-code)

---

## Security Fixes Summary

### 1. Password Security (BCrypt Integration)
- **Vulnerability**: Plaintext password storage
- **Fix**: Implemented BCrypt hashing with PasswordEncoder
- **Files**: `SecurityConfig.java`, `DataSeeder.java`, `AuthController.java`

### 2. JWT Security Hardening  
- **Vulnerability**: Weak JWT with no expiration
- **Fix**: Added issuer/audience claims, short TTL, proper key generation
- **Files**: `JwtService.java`, `SecurityConfig.java`

### 3. SecurityFilterChain & Access Control
- **Vulnerability**: Overly permissive endpoints
- **Fix**: Removed broad permitAll(), enabled proper authentication
- **Files**: `SecurityConfig.java`, `AuthController.java`

### 4. Resource Ownership Enforcement
- **Vulnerability**: BOLA/IDOR - no ownership checks
- **Fix**: Added ownership validation in all controllers
- **Files**: `UserController.java`, `AccountController.java`

### 5. DTO Implementation & Data Exposure
- **Vulnerability**: Excessive data exposure
- **Fix**: Created DTOs to hide sensitive fields
- **Files**: `UserDTO.java`, `CreateUserDTO.java`, `AdminUserDTO.java`, `UpdateUserDTO.java`

### 6. Rate Limiting
- **Vulnerability**: No rate limiting on sensitive endpoints
- **Fix**: Implemented custom RateLimitService with configurable limits
- **Files**: `RateLimitService.java`, all controllers

### 7. Mass Assignment Prevention
- **Vulnerability**: Role/isAdmin fields bindable via JSON
- **Fix**: Protected setters, separate DTOs, partial updates
- **Files**: `AppUser.java`, DTOs, `UserController.java`

### 8. Error Handling & Logging
- **Vulnerability**: Detailed error exposure
- **Fix**: Generic error messages, secure logging, security event tracking
- **Files**: `GlobalErrorHandler.java`, `application.properties`

### 9. Input Validation
- **Vulnerability**: Weak input validation
- **Fix**: Custom validators, enhanced DTO validation, SQL injection prevention
- **Files**: Custom validators, DTOs, controllers

### 10. Testing & Verification
- **Implementation**: Comprehensive security integration tests
- **Coverage**: All security features tested and verified
- **Files**: `SecurityIntegrationTests.java`, `AdditionalSecurityExpectationsTests.java`

---

## Key Code Changes Highlights

### BCrypt Password Hashing
```java
// Before: Plaintext
AppUser.builder().password("alice123")

// After: BCrypt hashed  
AppUser.builder().password(passwordEncoder.encode("alice123"))

### JWT Security Hardening
```java
// Enhanced JWT with security claims
return Jwts.parserBuilder()
    .setSigningKey(signingKey)
    .requireIssuer(jwtIssuer)
    .requireAudience("owasp-api-users")
    .build()
### Resource Ownership Enforcement
```java
// Ownership check in controllers
if (!user.getUsername().equals(currentUsername) && !isAdmin(auth)) {
    return ResponseEntity.status(403).body("Access denied");
}
### Rate Limiting Implementation
```java
// Rate limiting on sensitive endpoints
if (!rateLimitService.allowRequest(rateLimitKey, "login")) {
    return ResponseEntity.status(429).body("Too many requests");
}
### Security Impact Assessment

| Vulnerability | Risk Level | Fix Effectiveness |
|---------------|------------|-------------------|
| Plaintext Passwords | Critical | Complete - BCrypt implemented |
| JWT Weaknesses | High | Complete - All JWT best practices |
| Broken Access Control | High | Complete - Ownership checks added |
| Excessive Data Exposure | Medium | Complete - DTOs implemented |
| Mass Assignment | Medium | Complete - Protected setters & DTOs |
| Rate Limiting | Medium | Complete - Custom service implemented |
| Input Validation | Medium | Complete - Comprehensive validation |

### Test Results
All security integration tests passing:

✅ BCrypt password hashing verified  
✅ JWT security features working  
✅ Access control enforced  
✅ Ownership checks functional  
✅ Rate limiting operational  
✅ Input validation effective  
✅ Error handling secure  

### Conclusion
All 10 required security fixes have been successfully implemented, tested, and verified. The application now follows industry security best practices and is protected against OWASP API Security Top 10 vulnerabilities. Each fix was committed separately with descriptive messages and proper code comments.

**Total Security Fixes: 10/10 - COMPLETE**