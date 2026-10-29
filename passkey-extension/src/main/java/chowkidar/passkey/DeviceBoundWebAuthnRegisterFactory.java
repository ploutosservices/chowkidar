/*
 * Copyright 2026 Ploutos Services LLC
 * SPDX-License-Identifier: Apache-2.0
 */
package chowkidar.passkey;

import com.webauthn4j.verifier.attestation.trustworthiness.certpath.CertPathTrustworthinessVerifier;

import org.keycloak.authentication.requiredactions.WebAuthnRegister;
import org.keycloak.authentication.requiredactions.WebAuthnRegisterFactory;
import org.keycloak.models.KeycloakSession;

/**
 * Takes the place of Keycloak's "webauthn-register" (same id, higher order), because that id is what the
 * account console and the WebAuthn authenticators ask for. It records the backup-eligible
 * flag whether or not the realm sets {@value Passkeys#REALM_REFUSE_BACKUP_ELIGIBLE}; the record only matters where the
 * realm does, and registration is otherwise Keycloak's own.
 */
public class DeviceBoundWebAuthnRegisterFactory extends WebAuthnRegisterFactory {

    @Override
    protected WebAuthnRegister createProvider(KeycloakSession session, CertPathTrustworthinessVerifier verifier) {
        return new DeviceBoundWebAuthnRegister(session, verifier);
    }

    @Override
    public int order() {
        return 100;
    }
}
