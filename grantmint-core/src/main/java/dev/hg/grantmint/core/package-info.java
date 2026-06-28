/**
 * Grantmint core: the pure-Java, framework-agnostic crypto and issuance library.
 *
 * <p>This module is the correctness boundary of the product. It contains Ed25519 key
 * management, signed-token construction and verification, the short license key-ID scheme,
 * and entitlement encoding — all over plain bytes, strings, and {@code java.time} types with
 * <strong>zero</strong> Spring, Jakarta, or JSON-binding dependencies. That boundary is
 * enforced by {@code dev.hg.grantmint.core.ArchitectureTest} and is non-negotiable: it keeps
 * the core trivially property-testable, reusable by the CLI and the Apache-2.0 verifiers, and
 * friendly to GraalVM native-image (no reflection metadata to chase).
 *
 * @see <a href="file:../../../../../../docs/architecture/ARCHITECTURE.md">ARCHITECTURE.md</a>
 */
package dev.hg.grantmint.core;
