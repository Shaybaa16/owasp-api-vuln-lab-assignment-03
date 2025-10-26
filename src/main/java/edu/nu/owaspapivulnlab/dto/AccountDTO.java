package edu.nu.owaspapivulnlab.dto;

public class AccountDTO {
    
    private Long id;
    private String iban;
    private Double balance;
    
    // SECURITY FIX: Do not expose ownerUserId to prevent information leakage
    
    // Default constructor
    public AccountDTO() {}
    
    // Constructor
    public AccountDTO(Long id, String iban, Double balance) {
        this.id = id;
        this.iban = iban;
        this.balance = balance;
    }
    
    // Getters and setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    
    public String getIban() { return iban; }
    public void setIban(String iban) { this.iban = iban; }
    
    public Double getBalance() { return balance; }
    public void setBalance(Double balance) { this.balance = balance; }
}