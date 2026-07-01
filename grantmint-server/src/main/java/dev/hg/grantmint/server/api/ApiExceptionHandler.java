package dev.hg.grantmint.server.api;

import dev.hg.grantmint.core.license.IllegalLicenseTransitionException;
import dev.hg.grantmint.server.activation.ActivationNotFoundException;
import dev.hg.grantmint.server.activation.SeatLimitExceededException;
import dev.hg.grantmint.server.validation.LicenseNotValidException;
import dev.hg.grantmint.server.validation.RateLimitExceededException;
import java.util.NoSuchElementException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * Translates service-layer exceptions to the shared {@link ApiError} envelope: a missing entity
 * becomes 404, an invalid argument becomes 400, an authentic-but-unusable license becomes 422, and
 * an over-limit caller becomes 429 with {@code Retry-After}. Security denials (401/403) are handled
 * earlier by {@code SecurityErrorResponder} and never reach here.
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

    /**
     * The node-locked seat limit blocked a new fingerprint — a 409 with the stable code
     * {@code seat_limit_exceeded}. A recoverable, user-facing condition ("deactivate another
     * device"), distinct from the 422 stop-granting-entitlements family.
     */
    @ExceptionHandler(SeatLimitExceededException.class)
    ResponseEntity<ApiError> handleSeatLimit(SeatLimitExceededException ex) {
        return ResponseEntity.status(HttpStatus.CONFLICT).body(new ApiError("seat_limit_exceeded", ex.getMessage()));
    }

    /**
     * A lifecycle event applied to a state it is not legal from (e.g. reinstating a revoked
     * license) — a 409 with {@code invalid_state_transition}. The state machine's refusal is the
     * product working: nothing may ever silently un-revoke.
     */
    @ExceptionHandler(IllegalLicenseTransitionException.class)
    ResponseEntity<ApiError> handleIllegalTransition(IllegalLicenseTransitionException ex) {
        return ResponseEntity.status(HttpStatus.CONFLICT)
                .body(new ApiError("invalid_state_transition", ex.getMessage()));
    }

    /** No active seat for this fingerprint — a 404 with {@code activation_not_found}. */
    @ExceptionHandler(ActivationNotFoundException.class)
    ResponseEntity<ApiError> handleActivationNotFound(ActivationNotFoundException ex) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(new ApiError("activation_not_found", ex.getMessage()));
    }

    /**
     * The hot-path rate limit was exceeded — a 429 carrying {@code Retry-After} (whole seconds) so a
     * client can back off precisely rather than hammering. See docs/api/API_DOCUMENTATION.md.
     */
    @ExceptionHandler(RateLimitExceededException.class)
    ResponseEntity<ApiError> handleRateLimited(RateLimitExceededException ex) {
        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                .header(HttpHeaders.RETRY_AFTER, Long.toString(ex.retryAfterSeconds()))
                .body(new ApiError("rate_limited", ex.getMessage()));
    }
}
