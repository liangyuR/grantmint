package dev.hg.grantmint.server.domain;

import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;

/**
 * Maps {@link LicenseStatus} to its lowercase database token and back, keeping the persisted
 * value aligned with the {@code ck_licenses_status} CHECK constraint. Applied explicitly via
 * {@code @Convert} on {@link License#status} rather than auto-applied.
 */
@Converter
public class LicenseStatusConverter implements AttributeConverter<LicenseStatus, String> {

    @Override
    public String convertToDatabaseColumn(LicenseStatus attribute) {
        return attribute == null ? null : attribute.wire();
    }

    @Override
    public LicenseStatus convertToEntityAttribute(String dbData) {
        return dbData == null ? null : LicenseStatus.fromWire(dbData);
    }
}
