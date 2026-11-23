package dev.hg.grantmint.server.offline;

public class OfflineLicenseException extends RuntimeException {
    private final int status;
    private final String code;

    public OfflineLicenseException(int status, String code) {
        super(code);
        this.status = status;
        this.code = code;
    }

    public int status() {
        return status;
    }

    public String code() {
        return code;
    }
}
