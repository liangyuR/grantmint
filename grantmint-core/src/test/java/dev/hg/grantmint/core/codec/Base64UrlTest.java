package dev.hg.grantmint.core.codec;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class Base64UrlTest {

    @Test
    void encodesWithoutPaddingAndRoundTrips() {
        byte[] original = "grantmint".getBytes(StandardCharsets.UTF_8);
        String encoded = Base64Url.encode(original);

        assertThat(encoded).doesNotContain("=");
        assertThat(Base64Url.decode(encoded)).isEqualTo(original);
    }

    @Test
    void usesUrlSafeAlphabet() {
        // 0xFB 0xFF encodes to "-_" in the URL-safe alphabet (would be "+/" in standard base64).
        assertThat(Base64Url.encode(new byte[] {(byte) 0xFB, (byte) 0xFF})).isEqualTo("-_8");
    }

    @Test
    void rejectsPaddedInput() {
        assertThatThrownBy(() -> Base64Url.decode("Z3JhbnRtaW50=="))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("padding");
    }

    @Test
    void rejectsNonAlphabetInput() {
        // '+' and '/' belong to standard base64, not the URL-safe alphabet.
        assertThatThrownBy(() -> Base64Url.decode("ab+/")).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rejectsNonCanonicalTrailingBits() {
        // "AA" and "AC" both decode to the single byte 0x00 under the lenient JDK decoder — the
        // final character's unused low bits are silently discarded. Only the canonical form (all
        // unused bits zero) may decode; every alternate spelling of the same bytes is malformed.
        assertThat(Base64Url.decode("AA")).isEqualTo(new byte[] {0});
        assertThatThrownBy(() -> Base64Url.decode("AC"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("canonical");
        // Two-byte remainder group: 2 unused bits in the third character.
        assertThat(Base64Url.decode("AAA")).isEqualTo(new byte[] {0, 0});
        assertThatThrownBy(() -> Base64Url.decode("AAB")).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void everyNonCanonicalSpellingOfACanonicalSegmentIsRejected() {
        // For a 1-byte-remainder segment the final character carries 4 unused bits => 15 alternate
        // spellings decode to identical bytes. All 15 must be rejected; the canonical one accepted.
        String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        String canonical = Base64Url.encode(new byte[] {42});
        char last = canonical.charAt(canonical.length() - 1);
        int value = alphabet.indexOf(last);
        for (int bits = 1; bits <= 15; bits++) {
            String variant = canonical.substring(0, canonical.length() - 1) + alphabet.charAt(value | bits);
            assertThatThrownBy(() -> Base64Url.decode(variant))
                    .as("non-canonical variant '%s' of '%s'", variant, canonical)
                    .isInstanceOf(IllegalArgumentException.class);
        }
        assertThat(Base64Url.decode(canonical)).isEqualTo(new byte[] {42});
    }
}
