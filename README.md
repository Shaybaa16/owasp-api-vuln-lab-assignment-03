# OWASP API Vulnerability Lab - Secured Version

## Assignment 03 - Secure Software Design - Fall 2025

### 📋 Project Overview
This repository contains the **secured version** of the OWASP API Vulnerability Lab after implementing all required security fixes as per Assignment 03 requirements.

### 🛡️ Security Fixes Implemented

| # | Security Fix | Status | Key Changes |
|---|-------------|--------|-------------|
| 1 | Password Security (BCrypt) | ✅ Complete | BCrypt hashing, PasswordEncoder |
| 2 | JWT Security Hardening | ✅ Complete | Issuer/audience claims, short TTL |
| 3 | SecurityFilterChain & Access Control | ✅ Complete | Proper authentication, RBAC |
| 4 | Resource Ownership Enforcement | ✅ Complete | BOLA/IDOR protection |
| 5 | DTO Implementation & Data Exposure | ✅ Complete | Sensitive field protection |
| 6 | Rate Limiting | ✅ Complete | Custom RateLimitService |
| 7 | Mass Assignment Prevention | ✅ Complete | Protected setters, DTOs |
| 8 | Error Handling & Logging | ✅ Complete | Secure error handling |
| 9 | Input Validation | ✅ Complete | Custom validators |
| 10 | Testing & Verification | ✅ Complete | Security integration tests |

### 🌟 Branch Structure

- **`vulnerable-code`**: Original vulnerable codebase
- **`fixed-code`**: Secured implementation (current branch)

### 🔗 Pull Request
**Security Fixes Implementation**: [View Pull Request](https://github.com/Shaybaa16/owasp-api-vuln-lab-assignment-03/pull/1)

### 📊 Security Assessment
All 10 security fixes have been successfully implemented, tested, and verified. The application now follows industry security best practices and is protected against OWASP API Security Top 10 vulnerabilities.

### Documentation
#### For detailed vulnerability analysis and fix implementation, see:

#### Security_Fixes_Report.md

#### Individual commit messages for each security fix

### 🚀 Quick Start

```bash
# Clone the repository
git clone https://github.com/Shaybaa16/owasp-api-vuln-lab-assignment-03.git

# Switch to fixed branch
git checkout fixed-code

# Run the application
mvn spring-boot:run

# Testing
## Run security tests to verify all fixes:

```bash
mvn test


