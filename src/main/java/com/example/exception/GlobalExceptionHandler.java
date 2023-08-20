package com.example.exception;

import com.example.security.exception.JwtSecurityException;
import jakarta.validation.ConstraintViolationException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.validation.BindException;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;

import java.util.Date;

import static org.springframework.http.HttpStatus.UNPROCESSABLE_ENTITY;

@ControllerAdvice
@Slf4j
public class GlobalExceptionHandler {
	public static final String CHECK_ERROR_FIELD_MESSAGE = "Validation error. Check 'errors' field for details.";

	@ExceptionHandler({MethodArgumentNotValidException.class, BindException.class})
	protected ResponseEntity<ErrorResponse> handleMethodArgumentNotValid(BindException ex,
															 WebRequest request) {
		ErrorResponse errorResponse = new ErrorResponse(
			new Date(), UNPROCESSABLE_ENTITY.value(),
			CHECK_ERROR_FIELD_MESSAGE, request.getDescription(false)
		);

		BindingResult bindingResult = ex.getBindingResult();
		bindingResult.getFieldErrors().forEach(errorResponse::addValidationError);
		bindingResult.getGlobalErrors().forEach(errorResponse::addValidationError);

		log.debug("BindException :: ", ex);
		return ResponseEntity.unprocessableEntity().body(errorResponse);
	}

	@ExceptionHandler(ConstraintViolationException.class)
	public ResponseEntity<ErrorResponse> handleConstraintViolationException(ConstraintViolationException ex,
																WebRequest request) {
		ErrorResponse errorResponse = new ErrorResponse(
			new Date(), HttpStatus.BAD_REQUEST.value(),
			ex.getMessage(), request.getDescription(false)
		);
		log.debug("ConstraintViolationException ::", ex);
		return new ResponseEntity<>(errorResponse, HttpStatus.BAD_REQUEST);
	}

	@ExceptionHandler(MethodArgumentTypeMismatchException.class)
	public ResponseEntity<ErrorResponse> methodArgumentNotMatching(MethodArgumentTypeMismatchException ex,
																   WebRequest request) {
		ErrorResponse errorResponse =
				new ErrorResponse(new Date(), HttpStatus.BAD_REQUEST.value(),
						ex.getMessage(), request.getDescription(false));
		log.debug("MethodArgumentTypeMismatchException ::", ex);
		return new ResponseEntity<>(errorResponse, HttpStatus.BAD_REQUEST);
	}

	@ExceptionHandler(MissingServletRequestParameterException.class)
	public ResponseEntity<ErrorResponse> missingRequestParameter(MissingServletRequestParameterException ex,
																 WebRequest request) {
		ErrorResponse errorResponse =
				new ErrorResponse(new Date(), HttpStatus.BAD_REQUEST.value(),
						ex.getMessage(), request.getDescription(false));
		log.debug("MissingServletRequestParameterException ::", ex);
		return new ResponseEntity<>(errorResponse, HttpStatus.BAD_REQUEST);
	}

	@ExceptionHandler(HttpMessageNotReadableException.class)
	public ResponseEntity<ErrorResponse> httpMessageNotReadable(HttpMessageNotReadableException ex,
																WebRequest request) {
		ErrorResponse errorResponse =
				new ErrorResponse(new Date(), HttpStatus.BAD_REQUEST.value(),
						ex.getMessage(), request.getDescription(false));
		log.debug("HttpMessageNotReadableException ::", ex);
		return new ResponseEntity<>(errorResponse, HttpStatus.BAD_REQUEST);
	}

	@ExceptionHandler(AccessDeniedException.class)
	public ResponseEntity<ErrorResponse> handleAccessDeniedException(AccessDeniedException accessDeniedException,
																	 WebRequest request) {
		ErrorResponse errorResponse = new ErrorResponse(
			new Date(), HttpStatus.FORBIDDEN.value(),
			accessDeniedException.getMessage(), request.getDescription(false)
		);
		log.error(
			"AccessDeniedException Happened On Request:: {}",
			request.getDescription(true), accessDeniedException
		);
		return new ResponseEntity<>(errorResponse, HttpStatus.FORBIDDEN);
	}

	@ExceptionHandler(JwtSecurityException.class)
	public ResponseEntity<ErrorResponse> handleJwtSecurityException(JwtSecurityException jwtSecurityException,
																	WebRequest request) {
		JwtSecurityException.JWTErrorCode jwtErrorCode = jwtSecurityException.getJwtErrorCode();
		ErrorResponse errorResponse = new ErrorResponse(
			new Date(), jwtErrorCode.getErrorCode(),
			jwtSecurityException.getMessage(), request.getDescription(false)
		);
		log.error(
			"JwtSecurityException Happened On Request:: {}",
			request.getDescription(true), jwtSecurityException
		);
		return new ResponseEntity<>(errorResponse, jwtErrorCode.httpStatus());
	}

	@ExceptionHandler(Exception.class)
	public ResponseEntity<ErrorResponse> globalExceptionHandling(Exception exception,
																 WebRequest request){
		ErrorResponse errorResponse =
				new ErrorResponse(new Date(), HttpStatus.INTERNAL_SERVER_ERROR.value(),
						exception.getMessage(), request.getDescription(false));
		log.error("Internal System Exception ::", exception);
		return new ResponseEntity<>(errorResponse, HttpStatus.INTERNAL_SERVER_ERROR);
	}
}