package dev.hg.grantmint.server.api;

import dev.hg.grantmint.server.validation.LicenseNotValidException;
import java.util.NoSuchElementException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * Translates service-layer exceptions to the shared {@link ApiError} envelope: a missing entity
 * becomes 404, an invalid argument becomes 400, and an authentic-but-unusable license becomes 422.
 * Security denials (401/403) are handled earlier by {@code SecurityErrorResponder} and never reach
 * here.
 */
@RestControllerAdvice
public class ApiExceptionHandler {

    @ExceptionHandler(NoSuchElementException.class)
    ResponseEntity<ApiError> handleNotFound(NoSuchElementException ex) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(new ApiError("not_found", ex.getMessage()));
    }

    @ExceptionHandler(IllegalArgumentException.class)
    ResponseEntity<ApiError> handleBadRequest(IllegalArgumentException ex) {
        return ResponseEntity.badRequest().body(new ApiError("bad_request", ex.getMessage()));
    }

    /**
     * A revoked/suspended/expired/not-yet-valid license — a 422 carrying the stable reason code
     * ({@code license_revoked}, …). This is the {@code valid: false} validation outcome, distinct from
     * a 4xx for a malformed request or missing credentials.
     */
    @ExceptionHandler(LicenseNotValidException.class)
    ResponseEntity<ApiError> handleLicenseNotValid(LicenseNotValidException ex) {
        return ResponseEntity.status(HttpStatus.UNPROCESSABLE_ENTITY).body(new ApiError(ex.code(), ex.getMessage()));
    }
}
