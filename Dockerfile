# Chowkidar: Keycloak with the passkey extension and the chowkidar theme built in.
# The extension is built in a pinned Maven image; the pom fixes the build timestamp, so the same tree gives the
# same jar.
FROM maven:3.9.9-eclipse-temurin-21@sha256:3a4ab3276a087bf276f79cae96b1af04f53731bec53fb2e651aca79e4b10211e AS extension
WORKDIR /src
COPY passkey-extension/pom.xml .
RUN mvn -B -q dependency:go-offline
COPY passkey-extension/src src
RUN mvn -B -q -DskipTests package

FROM quay.io/keycloak/keycloak:26.4.4
COPY --from=extension /src/target/chowkidar-passkey.jar /opt/keycloak/providers/chowkidar-passkey.jar
COPY themes/chowkidar /opt/keycloak/themes/chowkidar
RUN /opt/keycloak/bin/kc.sh build --health-enabled=true
