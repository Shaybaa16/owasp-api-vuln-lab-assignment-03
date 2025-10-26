package edu.nu.owaspapivulnlab.web;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;

import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

@RestControllerAdvice
public class GlobalErrorHandler {

    private static final Logger logger = Logger.getLogger(GlobalErrorHandler.class.getName());

    // SECURITY FIX: Handle validation errors without exposing sensitive details
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, String>> handleValidationExceptions(
            MethodArgumentNotValidException ex) {
        
        Map<String, String> errors = new HashMap<>();
        ex.getBindingResult().getAllErrors().forEach((error) -> {
            String fieldName = ((FieldError) error).getField();
            String errorMessage = error.getDefaultMessage();
            errors.put(fieldName, errorMessage);
        });
        
        // SECURITY FIX: Log validation errors server-side but return generic message
        logger.warning("Validation error occurred: " + errors.toString());
        
        Map<String, String> response = new HashMap<>();
        response.put("error", "Validation failed");
        response.put("message", "Please check your input data");
        
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
    }

    // SECURITY FIX: Handle access denied exceptions
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<Map<String, String>> handleAccessDenied(AccessDeniedException ex) {
        // SECURITY FIX: Log access denied attempts
        logger.warning("Access denied: " + ex.getMessage());
        
        Map<String, String> response = new HashMap<>();
        response.put("error", "Access denied");
        response.put("message", "You don't have permission to access this resource");
        
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(response);
    }

    // SECURITY FIX: Handle generic exceptions without exposing details
    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, String>> handleAllExceptions(Exception ex, WebRequest request) {
        // SECURITY FIX: Log full error server-side but return generic message to client
        logger.severe("Internal server error: " + ex.getMessage());
        ex.printStackTrace(); // This goes to server logs only
        
        Map<String, String> response = new HashMap<>();
        response.put("error", "Internal server error");
        response.put("message", "An unexpected error occurred. Please try again later.");
        
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
    }

    // SECURITY FIX: Handle specific business logic exceptions
    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<Map<String, String>> handleBusinessExceptions(RuntimeException ex) {
        // SECURITY FIX: Log business exceptions but return user-friendly messages
        logger.warning("Business logic error: " + ex.getMessage());
        
        Map<String, String> response = new HashMap<>();
        
        // Provide specific messages for known business errors
        if (ex.getMessage().contains("not found")) {
            response.put("error", "Resource not found");
            response.put("message", "The requested resource was not found");
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(response);
        } else if (ex.getMessage().contains("already exists")) {
            response.put("error", "Conflict");
            response.put("message", "Resource already exists");
            return ResponseEntity.status(HttpStatus.CONFLICT).body(response);
        } else {
            response.put("error", "Operation failed");
            response.put("message", "The operation could not be completed");
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
        }
    }
}