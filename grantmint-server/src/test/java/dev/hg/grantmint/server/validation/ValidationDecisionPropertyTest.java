package dev.hg.grantmint.server.validation;

import static org.assertj.core.api.Assertions.assertThat;

import dev.hg.grantmint.server.domain.LicenseStatus;
import dev.hg.grantmint.server.validation.ValidationService.Decision;
import java.util.Map;
import java.util.UUID;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.constraints.IntRange;
import net.jqwik.api.constraints.LongRange;

/**
 * Property tests for {@link ValidationService#decide} — the pure heart of online validation. A wrong
 * decision here is a false security claim (a revoked license passing, or a healthy one failing), so
 * the full status × signature × temporal matrix is hammered rather than spot-checked.
 *
 * <p>The reference oracle is intentionally restated independently of the production switch: a license
 * is valid <em>iff</em> it is {@code ACTIVE}, signature-sound, at-or-after any {@code nbf}, and
 * strictly before any {@code exp}. Everything else must be rejected with the precedence-correct code.
 */
class ValidationDecisionPropertyTest {

    @Property(tries = 2000)
    void activeSoundAndInWindowIsAlwaysValid(
            @ForAll boolean hasNbf,
            @ForAll @LongRange(min = 0, max = 4_000_000_000L) long nbf,
            @ForAll boolean hasExp,
            @ForAll @LongRange(min = 0, max = 4_000_000_000L) long exp,
            @ForAll @LongRange(min = 0, max = 4_000_000_000L) long now,
            @ForAll @IntRange(min = 1, max = 100) int maxSeats) {
        ValidationSnapshot snapshot =
                snapshot(LicenseStatus.ACTIVE, true, hasNbf ? nbf : null, hasExp ? exp : null, maxSeats);

        Decision decision = ValidationService.decide(snapshot, now);

        boolean inWindow = (!hasNbf || now >= nbf) && (!hasExp || now < exp);
        assertThat(decision.valid()).isEqualTo(inWindow);
        if (inWindow) {
            assertThat(decision.code()).isNull();
        }
    }

    @Property(tries = 1000)
    void terminalAndBlockedStatusesAlwaysRejectRegardlessOfEverythingElse(
            @ForAll boolean signatureValid,
            @ForAll boolean hasExp,
            @ForAll @LongRange(min = 0, max = 4_000_000_000L) long exp,
            @ForAll @LongRange(min = 0, max = 4_000_000_000L) long now) {
        // Revoked / suspended / created / db-expired win over signature and temporal state.
        assertReject(
                LicenseStatus.REVOKED, signatureValid, hasExp ? exp : null, now, ValidationService.LICENSE_REVOKED);
        assertReject(
                LicenseStatus.SUSPENDED, signatureValid, hasExp ? exp : null, now, ValidationService.LICENSE_SUSPENDED);
        assertReject(
                LicenseStatus.EXPIRED, signatureValid, hasExp ? exp : null, now, ValidationService.LICENSE_EXPIRED);
        assertReject(
                LicenseStatus.CREATED, signatureValid, hasExp ? exp : null, now, ValidationService.LICENSE_INACTIVE);
    }

    @Property(tries = 1000)
    void activeButForgedTokenIsInvalid(
            @ForAll boolean hasExp,
            @ForAll @LongRange(min = 0, max = 4_000_000_000L) long exp,
            @ForAll @LongRange(min = 0, max = 4_000_000_000L) long now) {
        ValidationSnapshot snapshot = snapshot(LicenseStatus.ACTIVE, false, null, hasExp ? exp : null, 1);

        Decision decision = ValidationService.decide(snapshot, now);

        assertThat(decision.valid()).isFalse();
        assertThat(decision.code()).isEqualTo(ValidationService.LICENSE_INVALID);
    }

    @Property(tries = 1000)
    void activeSoundButExpiredReportsExpired(
            @ForAll @LongRange(min = 1, max = 4_000_000_000L) long exp,
            @ForAll @LongRange(min = 0, max = 4_000_000_000L) long delta) {
        long now = exp + delta; // now >= exp -> expired
        ValidationSnapshot snapshot = snapshot(LicenseStatus.ACTIVE, true, null, exp, 1);

        Decision decision = ValidationService.decide(snapshot, now);

        assertThat(decision.valid()).isFalse();
        assertThat(decision.code()).isEqualTo(ValidationService.LICENSE_EXPIRED);
    }

    @Property(tries = 1000)
    void activeSoundButBeforeNbfReportsNotYetValid(
            @ForAll @LongRange(min = 1, max = 4_000_000_000L) long nbf,
            @ForAll @LongRange(min = 1, max = 1_000_000L) long beforeBy) {
        long now = nbf - beforeBy; // now < nbf -> not yet valid (precedes the exp check)
        ValidationSnapshot snapshot = snapshot(LicenseStatus.ACTIVE, true, nbf, nbf + 1, 1);

        Decision decision = ValidationService.decide(snapshot, now);

        assertThat(decision.valid()).isFalse();
        assertThat(decision.code()).isEqualTo(ValidationService.LICENSE_NOT_YET_VALID);
    }

    private static void assertReject(LicenseStatus status, boolean sig, Long exp, long now, String expectedCode) {
        Decision decision = ValidationService.decide(snapshot(status, sig, null, exp, 1), now);
        assertThat(decision.valid()).isFalse();
        assertThat(decision.code()).isEqualTo(expectedCode);
    }

    private static ValidationSnapshot snapshot(LicenseStatus status, boolean sig, Long nbf, Long exp, int maxSeats) {
        return new ValidationSnapshot(
                UUID.randomUUID(), "acme-notes", status, sig, nbf, exp, maxSeats, Map.of("team_sync", true));
    }
}
