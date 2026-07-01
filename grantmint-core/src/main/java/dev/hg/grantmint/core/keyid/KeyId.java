package dev.hg.grantmint.core.keyid;

import java.security.SecureRandom;
import java.util.Locale;
import java.util.Objects;

/**
 * The short, human-typeable license key ID: {@code XXXX-XXXX-XXXX}.
 *
 * <p>Twelve significant characters in three hyphen-separated groups of four. The first eleven carry
 * the identifier entropy; the twelfth is a checksum over them. The key ID is the online handle a
 * human reads off an email or pastes into an app — so the design optimizes for being typed correctly
 * over the phone, not for density.
 *
 * <h2>Alphabet</h2>
 *
 * A 31-character Crockford-style alphabet, ambiguity-free (no {@code I L O U}, and no {@code Z} so
 * the count is exactly the prime 31):
 *
 * <pre>0123456789ABCDEFGHJKMNPQRSTVWXY</pre>
 *
 * <p>Eleven payload characters give ~11 · log2(31) ≈ 54.5 bits of entropy — collision-safe far
 * beyond any realistic license volume. The spec prose pins the alphabet size, {@link
 * SecureRandom#nextInt(int)} bound, and checksum modulus all to <strong>31</strong>; the modulus
 * being <em>prime</em> is what makes the checksum below provably catch every single-character error
 * and every adjacent transposition of distinct characters. See docs/features/LICENSE_TOKEN_FORMAT.md.
 *
 * <h2>Normalization</h2>
 *
 * Input is normalized before validation with {@link Locale#ROOT} (never the default locale — a
 * {@code tr_TR} JVM would otherwise mangle {@code I}), hyphens stripped, and the visually confusable
 * letters auto-corrected ({@code O→0}, {@code I→1}, {@code L→1}) so a customer who types {@code o} or
 * {@code l} still resolves.
 */
public final class KeyId {

    /** 31 characters; index == value in the checksum math. */
    static final String ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXY";

    private static final int RADIX = 31;
    private static final int PAYLOAD_LENGTH = 11;
    private static final int SIGNIFICANT_LENGTH = 12;

    private KeyId() {}

    /**
     * Generate a fresh, checksum-valid key ID such as {@code K7P2-9QXM-4T1Y}.
     *
     * @param random the randomness source for the eleven payload characters
     */
    public static String generate(SecureRandom random) {
        Objects.requireNonNull(random, "random");
        char[] significant = new char[SIGNIFICANT_LENGTH];
        for (int i = 0; i < PAYLOAD_LENGTH; i++) {
            significant[i] = ALPHABET.charAt(random.nextInt(RADIX));
        }
        significant[PAYLOAD_LENGTH] = checksumChar(significant, PAYLOAD_LENGTH);
        return group(new String(significant));
    }

    /**
     * Normalize a typed/stored key ID into canonical {@code XXXX-XXXX-XXXX} form.
     *
     * @throws InvalidKeyIdException if, after cleanup, it is not twelve valid characters with a
     *     correct checksum
     */
    public static String normalize(String typed) {
        Objects.requireNonNull(typed, "typed");
        String cleaned = typed.toUpperCase(Locale.ROOT)
                .replace("-", "")
                .replace('O', '0')
                .replace('I', '1')
                .replace('L', '1');
        if (cleaned.length() != SIGNIFICANT_LENGTH) {
            throw new InvalidKeyIdException(typed);
        }
        for (int i = 0; i < SIGNIFICANT_LENGTH; i++) {
            if (ALPHABET.indexOf(cleaned.charAt(i)) < 0) {
                throw new InvalidKeyIdException(typed);
            }
        }
        if (checksumChar(cleaned.toCharArray(), PAYLOAD_LENGTH) != cleaned.charAt(PAYLOAD_LENGTH)) {
            throw new InvalidKeyIdException(typed);
        }
        return group(cleaned);
    }

    /** Whether {@code typed} normalizes to a valid key ID (checksum included). */
    public static boolean isValid(String typed) {
        try {
            normalize(typed);
            return true;
        } catch (InvalidKeyIdException e) {
            return false;
        }
    }

    /** Weighted mod-31 checksum over the first {@code payloadLength} characters. */
    private static char checksumChar(char[] chars, int payloadLength) {
        int sum = 0;
        for (int i = 0; i < payloadLength; i++) {
            int value = ALPHABET.indexOf(chars[i]);
            // Position weights (i+1) differ per slot, so swapping two adjacent distinct characters
            // changes the sum; a prime modulus guarantees no single-character error maps back to 0.
            sum += value * (i + 1);
        }
        return ALPHABET.charAt(Math.floorMod(sum, RADIX));
    }

    /** Insert the two hyphens into 12 significant characters. */
    private static String group(String significant) {
        return significant.substring(0, 4) + "-" + significant.substring(4, 8) + "-" + significant.substring(8, 12);
    }
}
