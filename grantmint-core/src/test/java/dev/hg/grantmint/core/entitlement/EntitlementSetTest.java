package dev.hg.grantmint.core.entitlement;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;
import org.junit.jupiter.api.Test;

class EntitlementSetTest {

    @Test
    void encodeProducesFlatValueMap() {
        EntitlementSet set = EntitlementSet.of(
                Entitlement.flag("team_sync", true),
                Entitlement.limit("max_devices", 2),
                Entitlement.string("support_tier", "gold"));

        assertThat(set.encode())
                .containsEntry("team_sync", true)
                .containsEntry("max_devices", 2L)
                .containsEntry("support_tier", "gold");
    }

    @Test
    void decodeInfersTypesFromValues() {
        EntitlementSet set = EntitlementSet.decode(
                Map.of("team_sync", true, "max_devices", 5L, "max_projects", 10, "support_tier", "gold"));

        assertThat(set.isEnabled("team_sync")).isTrue();
        assertThat(set.limit("max_devices", -99)).isEqualTo(5L);
        assertThat(set.limit("max_projects", -99)).isEqualTo(10L);
        assertThat(set.string("support_tier", "none")).isEqualTo("gold");
    }

    @Test
    void accessorsReturnDefaultsForAbsentOrMistypedKeys() {
        EntitlementSet set = EntitlementSet.of(Entitlement.flag("team_sync", true));
        assertThat(set.isEnabled("absent")).isFalse();
        assertThat(set.limit("absent", 7)).isEqualTo(7);
        assertThat(set.string("absent", "def")).isEqualTo("def");
        // team_sync is a flag, not a limit/string — accessors of the wrong kind fall back.
        assertThat(set.limit("team_sync", 7)).isEqualTo(7);
        assertThat(set.string("team_sync", "def")).isEqualTo("def");
    }

    @Test
    void keysAreNormalizedWithRootLocale() {
        EntitlementSet set = EntitlementSet.of(Entitlement.flag("  Team_Sync ", true));
        assertThat(set.isEnabled("team_sync")).isTrue();
    }

    @Test
    void unlimitedSentinel() {
        Entitlement e = Entitlement.limit("max_projects", -1);
        assertThat(e.isUnlimited()).isTrue();
    }

    @Test
    void decodeEncodeRoundTripsEqual() {
        EntitlementSet original = EntitlementSet.of(
                Entitlement.flag("a", false), Entitlement.limit("b", -1), Entitlement.string("c", "x"));
        assertThat(EntitlementSet.decode(original.encode())).isEqualTo(original);
    }
}
