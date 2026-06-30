package dev.hg.grantmint.server.validation;

/**
 * Thrown when a license is authentic but not currently valid for use — revoked, suspended, expired,
 * not-yet-active, or carrying a token that fails signature/structure checks. Carries the stable
 * machine-readable {@code code} (e.g. {@code license_revoked}) the API renders as a {@code 422
 * Unprocessable Entity} with {@code valid: false} semantics. See docs/api/API_DOCUMENTATION.md.
 */
public class LicenseNotValidException extends RuntimeException {

    private final String code;

    public LicenseNotValidException(String code, String message) {
        super(message);
        this.code = code;
    }

    /** The stable reason code, e.g. {@code license_revoked} / {@code license_expired}. */
    public String code() {
        return code;
    }
}
