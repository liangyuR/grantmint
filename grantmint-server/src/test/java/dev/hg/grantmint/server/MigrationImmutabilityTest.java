package dev.hg.grantmint.server;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

/**
 * A committed Flyway migration is immutable — edit one and every already-migrated database fails
 * {@code flyway validate} on its stored checksum. The repository states this discipline in V4/V5/V7's
 * own headers, yet V3 was edited after its initial commit (caught by the post-M13 audit), proving
 * convention alone does not hold. This test pins each committed migration's SHA-256 so the build
 * fails the moment a released file changes, instead of a deployment failing later.
 *
 * <p>Adding a NEW migration is the normal, allowed operation: pin its checksum here in the same
 * commit (the assertion message prints the value to paste). Its version must also be greater than
 * every pinned version — back-filling a lower number would be skipped by already-migrated databases
 * (Flyway ignores versions below the applied baseline unless {@code outOfOrder} is on).
 */
class MigrationImmutabilityTest {

    /** SHA-256 of every committed migration, keyed by filename. Append-only, like the directory. */
    private static final Map<String, String> PINNED = Map.of(
            "V1__init.sql", "cb439c6282e238047bf70570a4a4e4a3e68aa2df96b18603a2883a55b8a25fea",
            "V2__validation_indexes.sql", "9f74f61ee89e5d9d06ef27f4835494abf2a22ab6b6290cac61029042a2a9462b",
            "V3__admin_auth.sql",
                    "c8c49a1cee3ead7225faabc3a06708b9e22313bb27748390cb24155bb0388863", // gitleaks:allow (checksum)
            "V4__api_key_prefix_check.sql",
                    "8676ff5c59a379781a385503aad1c667eeb7fe9823f6ae1f36f9c0ab6c8dee16", // gitleaks:allow (checksum)
            "V5__drop_redundant_key_id_active_index.sql",
                    "c80e1561a975aa3dffba29583216a54769b58278620380a54b7b7c146666425c",
            "V6__policy_code_index.sql", "643d98b683e3e0cf3e4d183d4732c635a587fdbf6939c1f7011fa74da50d458d",
            "V7__audit_index_gaps.sql", "f9c57eab4e3e9ed2a2eb8d9dfe6f9cbcd5d7b8fcd1ddf4a3db6c489d5b396517",
            "V8__offline_device_licenses.sql", "7a7cb67fcb42d1ae3b4dda066167f67b78f624c4e5719390f26de671b847a76c");

    private static final Pattern VERSIONED = Pattern.compile("V(\\d+)__.+\\.sql");

    @Test
    void committedMigrationsAreByteForByteUnchanged() {
        for (Map.Entry<String, String> pin : PINNED.entrySet()) {
            String actual = sha256OfResource("db/migration/" + pin.getKey());
            assertThat(actual)
                    .as(
                            "%s changed after being committed. NEVER edit a released migration — its Flyway"
                                    + " checksum is already stored in migrated databases; add a new V%d+ migration"
                                    + " instead. If this file is genuinely new-in-this-commit, pin: \"%s\"",
                            pin.getKey(), maxPinnedVersion() + 1, actual)
                    .isEqualTo(pin.getValue());
        }
    }

    @Test
    void everyMigrationIsPinnedAndNewOnesOnlyAppend() {
        List<String> onDisk = migrationFileNames();
        assertThat(onDisk)
                .as("migration directory must contain every pinned file")
                .containsAll(PINNED.keySet());
        int maxPinned = maxPinnedVersion();
        for (String name : onDisk) {
            if (PINNED.containsKey(name)) {
                continue;
            }
            assertThat(versionOf(name))
                    .as(
                            "%s is not pinned in this test. New migrations must append past V%d and be pinned"
                                    + " here in the same commit: \"%s\"",
                            name, maxPinned, sha256OfResource("db/migration/" + name))
                    .isGreaterThan(maxPinned);
        }
    }

    private static int maxPinnedVersion() {
        return PINNED.keySet().stream()
                .mapToInt(MigrationImmutabilityTest::versionOf)
                .max()
                .orElseThrow();
    }

    private static int versionOf(String fileName) {
        Matcher matcher = VERSIONED.matcher(fileName);
        assertThat(matcher.matches())
                .as("migration filename %s must match V<number>__<description>.sql", fileName)
                .isTrue();
        return Integer.parseInt(matcher.group(1));
    }

    /** The migration filenames on the test classpath (surefire runs against the exploded directory). */
    private static List<String> migrationFileNames() {
        URL url = MigrationImmutabilityTest.class.getClassLoader().getResource("db/migration");
        assertThat(url).as("db/migration must be on the classpath").isNotNull();
        try (Stream<Path> entries = Files.list(Path.of(url.toURI()))) {
            return entries.map(p -> p.getFileName().toString())
                    .filter(name -> name.toLowerCase(Locale.ROOT).endsWith(".sql"))
                    .sorted()
                    .toList();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        } catch (URISyntaxException e) {
            throw new IllegalStateException("db/migration is not a plain directory: " + url, e);
        }
    }

    private static String sha256OfResource(String resource) {
        try (InputStream in = MigrationImmutabilityTest.class.getClassLoader().getResourceAsStream(resource)) {
            assertThat(in).as("%s must be on the classpath", resource).isNotNull();
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(in.readAllBytes()));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
