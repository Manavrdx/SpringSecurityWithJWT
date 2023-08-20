package com.example.exception;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import org.springframework.validation.FieldError;
import org.springframework.validation.ObjectError;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Objects;

@Getter
@Setter
@RequiredArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ErrorResponse {
    private final Date timestamp;
    private final int status;
    private final String message;
    private final String details;
    private String stackTrace;
    private List<ValidationObjectError> errors;

    @Getter
    private static class ValidationFieldError extends ValidationObjectError {
        private final Object rejectedValue;
        private final String field;

        public ValidationFieldError(String field, String message, Object rejectedValue) {
            super(message);
            this.field = field;
            this.rejectedValue = rejectedValue;
        }
    }

    @AllArgsConstructor
    @Getter
    private static class ValidationObjectError {
        private String message;
    }

    public void addValidationError(FieldError fieldError){
        if(Objects.isNull(errors)) errors = new ArrayList<>();

        errors.add(fieldErrorToValidationError(fieldError));
    }

    public void addValidationError(ObjectError objectError) {
        if (Objects.isNull(errors)) errors = new ArrayList<>();
        errors.add(objectErrorToValidationError(objectError));
    }

    private ValidationObjectError objectErrorToValidationError(ObjectError objectError) {
        return new ValidationObjectError(objectError.getDefaultMessage());
    }

    private ValidationObjectError fieldErrorToValidationError(FieldError fieldError) {
        return new ValidationFieldError(
                fieldError.getField(),
                fieldError.getDefaultMessage(),
                fieldError.getRejectedValue()
        );
    }
}