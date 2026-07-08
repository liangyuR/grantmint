/**
 * JPA entities — the persistence model behind {@code grantmint-server}. The schema of record is
 * the Flyway migration set ({@code db/migration}); Hibernate only validates against it
 * ({@code ddl-auto: validate}), never generates DDL.
 *
 * <p><strong>Equality is deliberately identity-based.</strong> No entity here overrides
 * {@code equals}/{@code hashCode}: two references are equal only when they are the same managed
 * instance. That is safe in this model because every association is a unidirectional
 * {@code @ManyToOne} — no entity ever sits in a Hibernate-managed collection
 * ({@code @OneToMany}, {@code @ManyToMany}, {@code @ElementCollection}), which is exactly where
 * identity-vs-persisted-key equality diverges (a detached-then-merged element silently
 * "disappears" from a {@code Set}). {@code DomainModelArchitectureTest} build-enforces that
 * precondition; introduce persisted-key {@code equals}/{@code hashCode} BEFORE ever mapping a
 * managed collection (2026-07 audit, GRANTMINT-171).
 */
package dev.hg.grantmint.server.domain;
