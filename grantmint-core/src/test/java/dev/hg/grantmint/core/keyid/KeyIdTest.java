package dev.hg.grantmint.core.keyid;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.security.SecureRandom;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.constraints.IntRange;
import org.junit.jupiter.api.Test;

class KeyIdTest {

    private static final SecureRandom RNG = new SecureRandom();

    @Test
    void generatedKeyIdMatchesFormat() {
        String id = KeyId.generate(RNG);
        // Alphabet: 0-9 A-H J K M N P-T V-Y (no I, L, O, U, Z).
        String group = "[0-9A-HJKMNP-TV-Y]{4}";
        assertThat(id).matches(group + "-" + group + "-" + group);
    }

    @Test
    void normalizeFixesConfusableCharsAndCase() {
        String id = KeyId.generate(RNG); // canonical, all uppercase, no I/L/O
        // Lower-casing it and re-introducing confusable glyphs must still resolve to the same id.
        String mangled = id.toLowerCase(java.util.Locale.ROOT).replace('0', 'o').replace('1', 'l');
        assertThat(KeyId.normalize(mangled)).isEqualTo(id);
    }

    @Test
    void normalizeAcceptsMissingHyphens() {
        String id = KeyId.generate(RNG);
        assertThat(KeyId.normalize(id.replace("-", ""))).isEqualTo(id);
    }

    @Test
    void rejectsBadChecksum() {
        // U is outside the alphabet, guaranteeing an invalid id regardless of checksum.
        assertThatThrownBy(() -> KeyId.normalize("UUUU-UUUU-UUUU")).isInstanceOf(InvalidKeyIdException.class);
        assertThat(KeyId.isValid("UUUU-UUUU-UUUU")).isFalse();
    }

    @Test
    void rejectsWrongLength() {
        assertThat(KeyId.isValid("ABC")).isFalse();
    }

    /** Every generated id is valid and canonical (normalize is idempotent on its own output). */
    @Property(tries = 500)
    void generatedIdsAreValidAndCanonical() {
        String id = KeyId.generate(RNG);
        assertThat(KeyId.isValid(id)).isTrue();
        assertThat(KeyId.normalize(id)).isEqualTo(id);
    }

    /** Any single-character substitution within the alphabet is caught by the checksum. */
    @Property(tries = 500)
    void singleCharacterTypoIsDetected(@ForAll @IntRange(min = 0, max = 11) int position) {
        String id = KeyId.generate(RNG);
        String significant = id.replace("-", "");
        char original = significant.charAt(position);
        char replacement = original == 'Y' ? 'X' : 'Y'; // a different in-alphabet char
        char[] chars = significant.toCharArray();
        chars[position] = replacement;
        String typo = new String(chars);
        assertThat(KeyId.isValid(typo)).isFalse();
    }
}
