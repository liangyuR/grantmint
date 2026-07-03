# Hand-maintained GraalVM native-image hints for grantmint-server

This directory deliberately does NOT use the artifact's canonical
`dev.hg.grantmint/grantmint-server/` path: Spring Boot's `process-aot` writes its
generated config there and would silently shadow anything hand-written at the
same location (that exact clobbering shipped a broken first native build).

- `reflect-config.json` — two hint groups, both startup-fatal when missing:
  - `java.util.UUID[]` with `unsafeAllocated`: Hibernate 6.5's
    `MultiIdEntityLoaderArrayParam` reflectively allocates an array of the
    entity ID class while building the SessionFactory, and every Grantmint
    entity uses a UUID primary key. Spring Framework 6.1's `MemberCategory`
    cannot express `unsafeAllocated`, hence a raw GraalVM hint instead of a
    `RuntimeHintsRegistrar`. Failure mode: "Class java.util.UUID[] is
    instantiated reflectively but was never registered".
  - `com.github.benmanes.caffeine.cache.*`: Caffeine assembles its cache
    implementation classes by name at runtime from the builder's feature set
    (`SSMSW` = the validation snapshot cache's maximumSize+expireAfterWrite,
    `SSMSA` = the rate limiter's, plus their node classes and Unsafe field
    offsets). The variants Grantmint's builders produce are not all in the
    shipped reachability metadata; these entries were captured with the
    native-image tracing agent against a real boot + validate + scrape.
    Failure mode: `ClassNotFoundException: ...caffeine.cache.SSMSA` while
    creating `validationRateLimiter`. Adding a NEW Caffeine builder
    combination anywhere in the server may need a matching entry — re-run the
    tracing agent (see docs/operations/TROUBLESHOOTING.md) if the native
    binary dies on a caffeine class at boot.
