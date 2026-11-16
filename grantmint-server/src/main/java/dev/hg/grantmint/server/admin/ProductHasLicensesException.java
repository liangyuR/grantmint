package dev.hg.grantmint.server.admin;

public class ProductHasLicensesException extends RuntimeException {

    public ProductHasLicensesException() {
        super("Products with issued licenses cannot be deleted.");
    }
}
