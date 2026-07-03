# syntax=docker/dockerfile:1.7
#
# Fat-JAR fallback image for grantmint-server.
#
# NOTE ON DOCS vs CODE: docs/deployment/DOCKER_SETUP.md documents a GraalVM
# native-image primary Dockerfile plus a Gradle-based `Dockerfile.jvm`
# fallback (./gradlew, build.gradle.kts). This repository is actually a
# Maven multi-module reactor (pom.xml, ./mvnw) with no Gradle files and no
# native-image build wired up yet — see GRANTMINT-111. This Dockerfile is the
# fat-JAR fallback adapted to the real (Maven) build, per the task spec.
# It intentionally lives at grantmint-server/Dockerfile rather than the doc's
# root Dockerfile.jvm so the module that owns the artifact owns the image
# recipe too; the build CONTEXT is still the repo root (see docker-compose.yml)
# because Maven needs the full multi-module reactor to build grantmint-server.
#
# Build directly:
#   docker build -f grantmint-server/Dockerfile -t grantmint/server:0.1.0-jvm .
#
# Usual path: `docker compose build` (see root docker-compose.yml).

############################
# Stage 1 -- Maven build   #
############################
FROM eclipse-temurin:21-jdk AS build

WORKDIR /build

# Copy the wrapper + POMs first so dependency resolution is cached in its own
# layer and only invalidated when a POM actually changes (not on every source
# edit).
COPY mvnw ./
COPY .mvn ./.mvn
COPY pom.xml ./
COPY grantmint-core/pom.xml grantmint-core/pom.xml
COPY grantmint-server/pom.xml grantmint-server/pom.xml
COPY grantmint-spring-boot-starter/pom.xml grantmint-spring-boot-starter/pom.xml
COPY grantmint-cli/pom.xml grantmint-cli/pom.xml
RUN chmod +x mvnw

# Now the sources for the modules grantmint-server depends on (-am).
COPY grantmint-core grantmint-core
COPY grantmint-server grantmint-server
COPY grantmint-spring-boot-starter grantmint-spring-boot-starter
COPY grantmint-cli grantmint-cli

# Boot repackage (via the parent) produces the fat JAR at
# grantmint-server/target/grantmint-server-<version>.jar.
RUN ./mvnw -B -DskipTests -pl grantmint-server -am package

############################
# Stage 2 -- JRE runtime   #
############################
FROM eclipse-temurin:21-jre AS runtime

# eclipse-temurin's JRE base image ships neither curl nor wget; the
# HEALTHCHECK below needs one. curl is the smallest reliable option here.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

# Non-root service user; create /app owned by it before switching (WORKDIR
# alone would create the dir as root).
RUN useradd --system --no-create-home --uid 10001 --shell /usr/sbin/nologin grantmint \
    && mkdir -p /app \
    && chown grantmint:grantmint /app

COPY --from=build --chown=grantmint:grantmint \
    /build/grantmint-server/target/grantmint-server-0.1.0-SNAPSHOT.jar /app/app.jar

USER grantmint
WORKDIR /app

# 8080 = public API port (server.port); 9090 = actuator/management port
# (management.server.port in application.yml) carrying /actuator/health and
# /actuator/prometheus. See docs/operations/MONITORING_LOGGING.md: 9090 must
# never be published broadly (docker-compose.yml binds it to 127.0.0.1 only).
EXPOSE 8080 9090

ENV JAVA_OPTS="-XX:MaxRAMPercentage=75.0"

# Fat-JAR startup is JVM-speed (~1-2s), not the sub-50ms of a native image —
# give it a longer start_period than a native Dockerfile would need.
HEALTHCHECK --interval=15s --timeout=3s --start-period=45s --retries=5 \
    CMD curl -fsS http://127.0.0.1:9090/actuator/health || exit 1

ENTRYPOINT ["sh", "-c", "exec java $JAVA_OPTS -jar /app/app.jar"]
