package dev.hg.grantmint.client;

/** A hard entitlement gate ({@link EntitlementChecker#require}) found the feature not granted. */
public class EntitlementDeniedException extends RuntimeException {

    private final String entitlement;

    public EntitlementDeniedException(String entitlement) {
        super("Entitlement not granted by the current license: " + entitlement);
        this.entitlement = entitlement;
    }

    public String entitlement() {
        return entitlement;
    }
}
