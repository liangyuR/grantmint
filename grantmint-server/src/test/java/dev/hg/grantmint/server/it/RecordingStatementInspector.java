package dev.hg.grantmint.server.it;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import org.hibernate.resource.jdbc.spi.StatementInspector;

/**
 * Captures every SQL statement Hibernate emits, so a test can assert properties of the <em>actual
 * generated SQL</em> (not a hand-written approximation of it). Registered per test context via
 * {@code spring.jpa.properties.hibernate.session_factory.statement_inspector}; Hibernate
 * instantiates it reflectively, hence the static recording surface.
 */
public class RecordingStatementInspector implements StatementInspector {

    private static final List<String> STATEMENTS = new CopyOnWriteArrayList<>();

    @Override
    public String inspect(String sql) {
        STATEMENTS.add(sql);
        return sql;
    }

    static void clear() {
        STATEMENTS.clear();
    }

    /** The most recent captured statement containing the given fragment. */
    static String lastContaining(String fragment) {
        return STATEMENTS.reversed().stream()
                .filter(sql -> sql.contains(fragment))
                .findFirst()
                .orElseThrow(() -> new AssertionError("no captured SQL contains: " + fragment));
    }
}
