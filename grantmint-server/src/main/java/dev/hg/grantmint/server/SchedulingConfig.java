package dev.hg.grantmint.server;

import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;

/**
 * Turns on Spring's {@code @Scheduled} support for the background lifecycle jobs (the license
 * expiry sweep and the heartbeat-timeout reaper). Deliberately kept as its own bean rather than
 * placed on {@link GrantmintServerApplication} — a {@code @SpringBootTest} web-slice or component
 * test that boots the application class directly would otherwise start real scheduled jobs firing
 * against whatever datasource the test wires up, which is surprising and hard to reason about. Any
 * test slice that shouldn't run the jobs can exclude this configuration explicitly.
 */
@Configuration
@EnableScheduling
class SchedulingConfig {}
