/*
 * Copyright 2026 Ploutos Services LLC
 * SPDX-License-Identifier: Apache-2.0
 */
package chowkidar.passkey;

import com.webauthn4j.converter.AttestationObjectConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.verifier.attestation.trustworthiness.certpath.CertPathTrustworthinessVerifier;

import jakarta.ws.rs.core.MultivaluedMap;

import org.jboss.logging.Logger;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.requiredactions.WebAuthnRegister;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import org.keycloak.credential.CredentialModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;

/**
 * Keycloak's WebAuthn registration, plus one record: a credential whose authenticator data carries the
 * backup-eligible flag (BE, a synced passkey) is recorded on the user ({@value Passkeys#USER_BACKUP_ELIGIBLE})
 * once Keycloak has stored it. The flag is read from the authenticator data, which the browser sends whatever
 * the attestation preference; attestation is not requested. Approval and the higher level decide on
 * this record, never on attestation or an AAGUID. Everything else is Keycloak's own registration, unchanged.
 */
public class DeviceBoundWebAuthnRegister extends WebAuthnRegister {

    private static final Logger LOG = Logger.getLogger(DeviceBoundWebAuthnRegister.class);
    private static final AttestationObjectConverter CONVERTER = new AttestationObjectConverter(new ObjectConverter());

    public DeviceBoundWebAuthnRegister(KeycloakSession session, CertPathTrustworthinessVerifier verifier) {
        super(session, verifier);
    }

    @Override
    public void processAction(RequiredActionContext context) {
        byte[] syncedId = backupEligibleCredentialId(context);
        super.processAction(context);
        if (syncedId == null || context.getUser() == null) {
            return;
        }
        UserModel user = context.getUser();
        Optional<CredentialModel> stored = Passkeys.byWebAuthnId(user, Base64.getUrlEncoder().withoutPadding().encodeToString(syncedId));
        if (stored.isEmpty()) {
            return;   // Keycloak refused it; nothing stored, nothing to record
        }
        Set<String> ids = user.getAttributeStream(Passkeys.USER_BACKUP_ELIGIBLE)
                .collect(Collectors.toCollection(LinkedHashSet::new));
        ids.retainAll(Passkeys.credentialIds(user));
        ids.add(stored.get().getId());
        user.setAttribute(Passkeys.USER_BACKUP_ELIGIBLE, ids.stream().sorted().toList());
        LOG.infof("recorded WebAuthn credential %s of user %s in realm %s as backup-eligible (synced)",
                stored.get().getId(), user.getId(), context.getRealm().getName());
    }

    /** The WebAuthn credential id of a BE=1 registration, from its authenticator data; null otherwise. */
    private static byte[] backupEligibleCredentialId(RequiredActionContext context) {
        MultivaluedMap<String, String> form = context.getHttpRequest().getDecodedFormParameters();
        String error = form.getFirst("error");
        String attestation = form.getFirst("attestationObject");
        if ((error != null && !error.isEmpty()) || attestation == null || attestation.isEmpty()) {
            return null;   // Keycloak's own handling reports a cancelled or empty response
        }
        try {
            AttestationObject object = CONVERTER.convert(attestation);
            if (object == null || object.getAuthenticatorData() == null || !object.getAuthenticatorData().isFlagBE()
                    || object.getAuthenticatorData().getAttestedCredentialData() == null) {
                return null;
            }
            return object.getAuthenticatorData().getAttestedCredentialData().getCredentialId();
        } catch (RuntimeException e) {
            return null;   // malformed: Keycloak's own verification refuses it
        }
    }
}
