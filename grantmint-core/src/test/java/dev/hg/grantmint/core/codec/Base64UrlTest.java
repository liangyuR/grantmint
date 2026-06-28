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
}
