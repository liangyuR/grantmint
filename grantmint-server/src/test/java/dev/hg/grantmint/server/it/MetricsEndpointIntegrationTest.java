package dev.hg.grantmint.server.it;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.actuate.observability.AutoConfigureObservability;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalManagementPort;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

/**
 * The Prometheus scrape surface, end to end on a real server: {@code /actuator/prometheus} answers
 * on the <em>management</em> port with the {@code grantmint.}-prefixed meters (including the
 * DB-backed gauges, sampled live against real PostgreSQL), while the public API port serves no
 * actuator at all — the separate-port stance of docs/operations/MONITORING_LOGGING.md, since
 * requests outside the three auth chains bypass security entirely.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = "management.server.port=0")
// @SpringBootTest disables metrics export by default (DisableObservabilityContextCustomizer);
// this test exists precisely to exercise the real Prometheus registry, so opt back in.
@AutoConfigureObservability
class MetricsEndpointIntegrationTest extends PostgresIntegrationTest {

    @LocalServerPort
    private int serverPort;

    @LocalManagementPort
    private int managementPort;

    @Autowired
    private TestRestTemplate rest;

    @Test
    void prometheusEndpointServesGrantmintMetersOnTheManagementPort() {
        ResponseEntity<String> scrape =
                rest.getForEntity("http://localhost:" + managementPort + "/actuator/prometheus", String.class);

        assertThat(scrape.getStatusCode()).isEqualTo(HttpStatus.OK);
        // The DB-backed gauges are registered and sampled against the live database on scrape.
        assertThat(scrape.getBody()).contains("grantmint_licenses_active{");
        assertThat(scrape.getBody()).contains("grantmint_seats_used{");
    }

    @Test
    void publicApiPortServesNoActuator() {
        ResponseEntity<String> viaApiPort =
                rest.getForEntity("http://localhost:" + serverPort + "/actuator/prometheus", String.class);

        assertThat(viaApiPort.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
    }
}
