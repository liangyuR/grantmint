package dev.hg.grantmint.core.license;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.EnumMap;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;

/**
 * Property proof that the state machine implements the LICENSE_LIFECYCLE.md transition table
 * exactly: every legal (state, event) pair is accepted with the documented target, every other pair
 * throws {@link IllegalLicenseTransitionException} — and, sequence-wise, no chain of events ever
 * escapes REVOKED or re-activates EXPIRED except via RENEW.
 *
 * <p>The oracle below is written out pair-by-pair, independently of the production {@code switch},
 * so a table edit must be made twice to pass. One deliberate reconciliation, mirrored here: the
 * doc's transition table lists {@code expire} from active/suspended, while its own
 * {@code LicenseState} reachability includes CREATED→EXPIRED; the machine (and this oracle) side
 * with reachability and allow a never-activated license to expire.
 */
class LicenseStateMachinePropertyTest {

    /** The transition table, restated independently: from-state → (event → target). */
    private static final Map<LicenseState, Map<LicenseEvent, LicenseState>> TABLE = buildTable();

    private static Map<LicenseState, Map<LicenseEvent, LicenseState>> buildTable() {
        Map<LicenseState, Map<LicenseEvent, LicenseState>> table = new EnumMap<>(LicenseState.class);
        for (LicenseState s : LicenseState.values()) {
            table.put(s, new EnumMap<>(LicenseEvent.class));
        }
        table.get(LicenseState.CREATED).put(LicenseEvent.ACTIVATE, LicenseState.ACTIVE);
        table.get(LicenseState.CREATED).put(LicenseEvent.EXPIRE, LicenseState.EXPIRED);
        table.get(LicenseState.CREATED).put(LicenseEvent.REVOKE, LicenseState.REVOKED);
        table.get(LicenseState.ACTIVE).put(LicenseEvent.CONVERT_TRIAL, LicenseState.ACTIVE);
        table.get(LicenseState.ACTIVE).put(LicenseEvent.SUSPEND, LicenseState.SUSPENDED);
        table.get(LicenseState.ACTIVE).put(LicenseEvent.EXPIRE, LicenseState.EXPIRED);
        table.get(LicenseState.ACTIVE).put(LicenseEvent.REVOKE, LicenseState.REVOKED);
        table.get(LicenseState.SUSPENDED).put(LicenseEvent.REINSTATE, LicenseState.ACTIVE);
        table.get(LicenseState.SUSPENDED).put(LicenseEvent.EXPIRE, LicenseState.EXPIRED);
        table.get(LicenseState.SUSPENDED).put(LicenseEvent.REVOKE, LicenseState.REVOKED);
        table.get(LicenseState.EXPIRED).put(LicenseEvent.RENEW, LicenseState.ACTIVE);
        table.get(LicenseState.EXPIRED).put(LicenseEvent.REVOKE, LicenseState.REVOKED);
        // REVOKED: terminal — no legal event at all.
        return table;
    }

    /** Every (state, event) pair behaves exactly as the restated table says — accept or throw. */
    @Property(tries = 1000)
    void everyPairMatchesTheTransitionTable(@ForAll LicenseState from, @ForAll LicenseEvent event) {
        LicenseStateMachine machine = new LicenseStateMachine();
        LicenseState expected = TABLE.get(from).get(event);

        if (expected != null) {
            assertThat(machine.apply(from, event)).isEqualTo(expected);
            assertThat(machine.permits(from, event)).isTrue();
        } else {
            assertThatThrownBy(() -> machine.apply(from, event))
                    .isInstanceOf(IllegalLicenseTransitionException.class)
                    .hasMessageContaining(from.name())
                    .hasMessageContaining(event.name());
            assertThat(machine.permits(from, event)).isFalse();
        }
    }

    /** No event sequence, from any start state, ever leaves REVOKED once it is reached. */
    @Property(tries = 2000)
    void noSequenceEverEscapesRevoked(@ForAll LicenseState start, @ForAll("eventSequences") List<LicenseEvent> events) {
        LicenseStateMachine machine = new LicenseStateMachine();
        LicenseState state = start;
        boolean revoked = state == LicenseState.REVOKED;

        for (LicenseEvent event : events) {
            try {
                state = machine.apply(state, event);
            } catch (IllegalLicenseTransitionException rejected) {
                // Rejection leaves the state untouched — that is the whole guarantee.
            }
            if (revoked) {
                assertThat(state).isEqualTo(LicenseState.REVOKED);
            }
            revoked = revoked || state == LicenseState.REVOKED;
        }
    }

    /** EXPIRED only ever returns to ACTIVE through RENEW — REINSTATE must not resurrect it. */
    @Property(tries = 2000)
    void expiredOnlyLeavesViaRenewOrRevoke(@ForAll("eventSequences") List<LicenseEvent> events) {
        LicenseStateMachine machine = new LicenseStateMachine();
        LicenseState state = LicenseState.EXPIRED;

        for (LicenseEvent event : events) {
            LicenseState before = state;
            try {
                state = machine.apply(state, event);
            } catch (IllegalLicenseTransitionException rejected) {
                state = before;
            }
            if (before == LicenseState.EXPIRED && state != before) {
                assertThat(event).isIn(LicenseEvent.RENEW, LicenseEvent.REVOKE);
            }
        }
    }

    /** Every event edge that changes state is consistent with LicenseState.allowedTargets(). */
    @Property(tries = 100)
    void eventTableIsConsistentWithStateReachability(@ForAll LicenseState from, @ForAll LicenseEvent event) {
        LicenseState target = TABLE.get(from).get(event);
        if (target != null && target != from) {
            assertThat(from.canTransitionTo(target))
                    .as("event edge %s: %s -> %s must be reachable per allowedTargets()", event, from, target)
                    .isTrue();
        }
    }

    /** allowedTargets() carries no dead edges: every reachable change is driven by some event. */
    @Property(tries = 100)
    void everyReachableChangeIsDrivenBySomeEvent(@ForAll LicenseState from) {
        Set<LicenseState> drivenTargets = EnumSet.noneOf(LicenseState.class);
        TABLE.get(from).values().forEach(drivenTargets::add);
        drivenTargets.remove(from); // self-loops are not state changes

        assertThat(drivenTargets).isEqualTo(from.allowedTargets());
    }

    @Provide
    Arbitrary<List<LicenseEvent>> eventSequences() {
        return Arbitraries.of(LicenseEvent.class).list().ofMinSize(0).ofMaxSize(30);
    }
}
