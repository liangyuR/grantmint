package dev.hg.grantmint.server.it;

import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.testcontainers.containers.PostgreSQLContainer;

/**
 * Shared base for database-backed integration tests. Boots a <strong>real PostgreSQL 16</strong>
 * in Docker (never H2) so that real {@code UNIQUE}/{@code CHECK} constraints, transactional seat
 * counting, the Flyway migrations, and the JPA mapping are all exercised against the genuine
 * engine. See docs/testing/TESTING.md.
 *
 * <p>Uses the <em>singleton container</em> pattern: one container is started once in a static
 * initializer and shared by every test class for the whole JVM run (Ryuk reaps it at exit). This
 * deliberately avoids JUnit's {@code @Testcontainers}/{@code @Container} lifecycle, which stops the
 * container at the end of the first test class and would leave later classes pointing at a dead
 * port. {@link ServiceConnection} wires Spring Boot's datasource to the running container, so
 * Flyway migrates and Hibernate validates the mapping on context start.
 *
 * <p>⚠️ Docker must be running for any subclass to execute.
 */
public abstract class PostgresIntegrationTest {

    @ServiceConnection
    static final PostgreSQLContainer<?> POSTGRES =
            new PostgreSQLContainer<>("postgres:16-alpine").withDatabaseName("grantmint");

    static {
        POSTGRES.start();
    }
}
