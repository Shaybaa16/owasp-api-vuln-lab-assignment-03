package edu.nu.owaspapivulnlab.validation;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

public class AmountValidator implements ConstraintValidator<ValidAmount, Double> {
    
    private double min;
    private double max;
    
    @Override
    public void initialize(ValidAmount constraintAnnotation) {
        this.min = constraintAnnotation.min();
        this.max = constraintAnnotation.max();
    }
    
    @Override
    public boolean isValid(Double value, ConstraintValidatorContext context) {
        if (value == null) {
            return false;
        }
        
        // SECURITY FIX: Validate amount range and prevent special values
        if (Double.isNaN(value) || Double.isInfinite(value)) {
            return false;
        }
        
        if (value < min) {
            return false;
        }
        
        if (value > max) {
            return false;
        }
        
        // SECURITY FIX: Prevent overly precise values that could cause issues
        String valueStr = String.valueOf(value);
        if (valueStr.contains(".") && valueStr.split("\\.")[1].length() > 2) {
            return false; // Only allow up to 2 decimal places
        }
        
        return true;
    }
}