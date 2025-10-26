package edu.nu.owaspapivulnlab.web;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import edu.nu.owaspapivulnlab.model.Account;
import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.repo.AccountRepository;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;

// Add imports
import edu.nu.owaspapivulnlab.service.RateLimitService;
import jakarta.servlet.http.HttpServletRequest;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/accounts")
public class AccountController {

    private final AccountRepository accounts;
    private final AppUserRepository users;
    private final RateLimitService rateLimitService;

    // Update constructor to include RateLimitService
    public AccountController(AccountRepository accounts, AppUserRepository users, RateLimitService rateLimitService) {
        this.accounts = accounts;
        this.users = users;
        this.rateLimitService = rateLimitService;
    }

    // SECURITY FIX: Add ownership check for account balance
    @GetMapping("/{id}/balance")
    public ResponseEntity<?> balance(@PathVariable Long id) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String currentUsername = auth.getName();
        
        Optional<Account> account = accounts.findById(id);
        if (account.isEmpty()) {
            Map<String, String> error = new HashMap<>();
            error.put("error", "Account not found");
            return ResponseEntity.status(404).body(error);
        }
        
        Account acc = account.get();
        Optional<AppUser> accountOwner = users.findById(acc.getOwnerUserId());
        
        // SECURITY FIX: Check if current user owns the account or is admin
        if (accountOwner.isEmpty() || 
            (!accountOwner.get().getUsername().equals(currentUsername) && 
             !isAdmin(auth))) {
            Map<String, String> error = new HashMap<>();
            error.put("error", "Access denied");
            return ResponseEntity.status(403).body(error);
        }
        
        Map<String, Object> response = new HashMap<>();
        response.put("balance", acc.getBalance());
        response.put("accountId", acc.getId());
        
        return ResponseEntity.ok(response);
    }

    // SECURITY FIX: Add ownership check and input validation for transfers
    @PostMapping("/{id}/transfer")
    public ResponseEntity<?> transfer(@PathVariable Long id, @RequestParam Double amount, HttpServletRequest request) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String currentUsername = auth.getName();
        
        // SECURITY FIX: Apply rate limiting to transfers
        String clientIp = getClientIp(request);
        String rateLimitKey = "transfer_" + currentUsername + "_" + clientIp;
        
        if (!rateLimitService.allowRequest(rateLimitKey, "transfer")) {
            Map<String, String> error = new HashMap<>();
            error.put("error", "Too many transfer requests. Please try again in 1 minute.");
            return ResponseEntity.status(429).body(error);
        }
        
        // SECURITY FIX: Validate amount
        if (amount == null || amount <= 0) {
            Map<String, String> error = new HashMap<>();
            error.put("error", "Amount must be positive");
            return ResponseEntity.status(400).body(error);
        }
        
        Optional<Account> account = accounts.findById(id);
        if (account.isEmpty()) {
            Map<String, String> error = new HashMap<>();
            error.put("error", "Account not found");
            return ResponseEntity.status(404).body(error);
        }
        
        Account acc = account.get();
        Optional<AppUser> accountOwner = users.findById(acc.getOwnerUserId());
        
        // SECURITY FIX: Check if current user owns the account
        if (accountOwner.isEmpty() || !accountOwner.get().getUsername().equals(currentUsername)) {
            Map<String, String> error = new HashMap<>();
            error.put("error", "Access denied - can only transfer from own accounts");
            return ResponseEntity.status(403).body(error);
        }
        
        // SECURITY FIX: Check sufficient balance
        if (acc.getBalance() < amount) {
            Map<String, String> error = new HashMap<>();
            error.put("error", "Insufficient balance");
            return ResponseEntity.status(400).body(error);
        }
        
        // SECURITY FIX: Perform transfer
        acc.setBalance(acc.getBalance() - amount);
        accounts.save(acc);
        
        Map<String, Object> response = new HashMap<>();
        response.put("status", "ok");
        response.put("remaining", acc.getBalance());
        response.put("transferred", amount);
        
        return ResponseEntity.ok(response);
    }

    // SECURITY FIX: Return limited account information for user's own accounts
    @GetMapping("/mine")
    public ResponseEntity<?> mine() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String currentUsername = auth.getName();
        
        AppUser me = users.findByUsername(currentUsername).orElse(null);
        if (me == null) {
            return ResponseEntity.ok(Collections.emptyList());
        }
        
        List<Account> userAccounts = accounts.findByOwnerUserId(me.getId());
        
        // SECURITY FIX: Return limited account information
        List<Map<String, Object>> response = userAccounts.stream()
                .map(account -> {
                    Map<String, Object> accountInfo = new HashMap<>();
                    accountInfo.put("id", account.getId());
                    accountInfo.put("iban", account.getIban());
                    accountInfo.put("balance", account.getBalance());
                    return accountInfo;
                })
                .collect(Collectors.toList());
        
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