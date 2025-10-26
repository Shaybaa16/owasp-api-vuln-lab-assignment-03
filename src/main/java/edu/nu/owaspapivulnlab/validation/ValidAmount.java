package edu.nu.owaspapivulnlab.validation;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;
import java.lang.annotation.*;

@Documented
@Constraint(validatedBy = AmountValidator.class)
@Target({ElementType.FIELD, ElementType.PARAMETER})
@Retention(RetentionPolicy.RUNTIME)
public @interface ValidAmount {
    String message() default "Invalid amount";
    double min() default 0.01;
    double max() default 1000000;
    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};
}