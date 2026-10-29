/*
 * Copyright 2026 Ploutos Services LLC
 * SPDX-License-Identifier: Apache-2.0
 */
package chowkidar.passkey;

import java.util.Base64;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import org.keycloak.credential.CredentialModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.WebAuthnCredentialModel;
import org.keycloak.representations.userprofile.config.UPConfig;
import org.keycloak.userprofile.UserProfileProvider;

/** The names this extension reads and writes, and the lookups its parts share. */
final class Passkeys {

    /**
     * Realm attribute: "true" keeps a backup-eligible (BE=1, synced) WebAuthn credential away from the higher
     * level — it enrols and signs in, but is never approved and never verifies gold. Attestation is not requested, and synced keys enrol like any other.
     */
    static final String REALM_REFUSE_BACKUP_ELIGIBLE = "chowkidar.passkey.refuseBackupEligible";

    /**
     * User attribute (multi-valued): the ids of the user's WebAuthn credentials whose authenticator data
     * carried BE=1 at registration. Read from the authenticator data, never from attestation. A credential
     * that is not in it counts as device-bound.
     */
    static final String USER_BACKUP_ELIGIBLE = "chowkidar.passkey.backupEligible";

    /** User attribute (multi-valued): the ids of the user's WebAuthn credentials an administrator approved. */
    static final String USER_APPROVED = "chowkidar.passkey.approved";

    /** User-session note: the ids of the WebAuthn credentials that verified this session, comma-separated. */
    static final String SESSION_VERIFIED_BY = "chowkidar.passkey.verifiedBy";

    /**
     * Realm attribute: "true" lets a person holding an enrolled key sign in with it from the address page.
     * Off, the key is the step-up only. Turning it on in a realm is a deliberate administrator choice.
     */
    static final String REALM_KEY_SIGN_IN = "chowkidar.passkey.signIn";

    /** The realm's levels (acr.loa.map: silver 1, gold 2). */
    static final int SILVER = 1;
    static final int GOLD = 2;

    /** The two-factor WebAuthn credential type, the one this policy governs. */
    static final String TYPE = WebAuthnCredentialModel.TYPE_TWOFACTOR;

    private Passkeys() {}

    static boolean keySignIn(RealmModel realm) {
        return Boolean.parseBoolean(realm.getAttribute(REALM_KEY_SIGN_IN));
    }

    static boolean refuseBackupEligible(RealmModel realm) {
        return Boolean.parseBoolean(realm.getAttribute(REALM_REFUSE_BACKUP_ELIGIBLE));
    }

    /**
     * The approved ids. Fails closed: when the realm lets a user edit attributes the user profile does not
     * declare, a user could approve their own key, so nothing counts as approved.
     */
    static Set<String> approved(KeycloakSession session, UserModel user) {
        if (usersEditUndeclaredAttributes(session)) {
            return Set.of();
        }
        return user.getAttributeStream(USER_APPROVED).collect(Collectors.toCollection(LinkedHashSet::new));
    }

    /**
     * The ids recorded as backup-eligible. Fails closed like {@link #approved}: when a user could edit the
     * record, every one of the user's credentials counts as backup-eligible.
     */
    static Set<String> backupEligible(KeycloakSession session, UserModel user) {
        if (usersEditUndeclaredAttributes(session)) {
            return credentialIds(user);
        }
        return user.getAttributeStream(USER_BACKUP_ELIGIBLE).collect(Collectors.toCollection(LinkedHashSet::new));
    }

    /** True when the realm keeps synced keys off the higher level and this credential is recorded as one. */
    static boolean keptOffGold(KeycloakSession session, RealmModel realm, UserModel user, String credentialId) {
        return refuseBackupEligible(realm) && backupEligible(session, user).contains(credentialId);
    }

    static boolean usersEditUndeclaredAttributes(KeycloakSession session) {
        UserProfileProvider up = session.getProvider(UserProfileProvider.class);
        UPConfig config = up == null ? null : up.getConfiguration();
        return config != null && config.getUnmanagedAttributePolicy() == UPConfig.UnmanagedAttributePolicy.ENABLED;
    }

    static void setApproved(UserModel user, Set<String> ids) {
        if (ids.isEmpty()) {
            user.removeAttribute(USER_APPROVED);
        } else {
            user.setAttribute(USER_APPROVED, ids.stream().sorted().toList());
        }
    }

    static Set<String> credentialIds(UserModel user) {
        return user.credentialManager().getStoredCredentialsByTypeStream(TYPE)
                .map(CredentialModel::getId).collect(Collectors.toSet());
    }

    /** The stored credential whose WebAuthn credential id (as the browser sends it) is {@code webAuthnId}. */
    static Optional<CredentialModel> byWebAuthnId(UserModel user, String webAuthnId) {
        byte[] wanted = decode(webAuthnId);
        if (wanted == null) {
            return Optional.empty();
        }
        return user.credentialManager().getStoredCredentialsByTypeStream(TYPE)
                .filter(c -> {
                    try {
                        byte[] stored = decode(WebAuthnCredentialModel.createFromCredentialModel(c)
                                .getWebAuthnCredentialData().getCredentialId());
                        return stored != null && Arrays.equals(stored, wanted);
                    } catch (RuntimeException e) {
                        return false;
                    }
                })
                .findFirst();
    }

    /** Base64 in either alphabet, padded or not. */
    static byte[] decode(String s) {
        if (s == null || s.isEmpty()) {
            return null;
        }
        try {
            return Base64.getUrlDecoder().decode(s.replace('+', '-').replace('/', '_').replaceAll("=+$", ""));
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    static Set<String> splitNote(String note) {
        Set<String> out = new LinkedHashSet<>();
        if (note != null) {
            for (String id : note.split(",")) {
                if (!id.isBlank()) {
                    out.add(id.trim());
                }
            }
        }
        return out;
    }
}
