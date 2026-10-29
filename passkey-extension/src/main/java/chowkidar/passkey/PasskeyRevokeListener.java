/*
 * Copyright 2026 Ploutos Services LLC
 * SPDX-License-Identifier: Apache-2.0
 */
package chowkidar.passkey;

import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.jboss.logging.Logger;
import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventType;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.events.admin.OperationType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.services.managers.AuthenticationManager;

/**
 * When a user's WebAuthn credential is deleted (by the user in the account console, or by an administrator),
 * every session that credential verified is ended, and its approval is withdrawn. A session verified only
 * by a credential that still exists is left alone. Enabled per realm by listing this listener in the
 * realm's event listeners.
 */
public class PasskeyRevokeListener implements EventListenerProvider {

    private static final Logger LOG = Logger.getLogger(PasskeyRevokeListener.class);
    private static final Pattern CREDENTIAL_PATH = Pattern.compile("^users/([^/]+)/credentials/[^/]+/?$");

    private final KeycloakSession session;

    PasskeyRevokeListener(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public void onEvent(Event event) {
        if (event.getType() == EventType.REMOVE_CREDENTIAL && event.getError() == null && event.getUserId() != null) {
            reconcile(event.getRealmId(), event.getUserId());
        }
    }

    @Override
    public void onEvent(AdminEvent event, boolean includeRepresentation) {
        OperationType op = event.getOperationType();
        if ((op != OperationType.DELETE && op != OperationType.ACTION) || event.getResourcePath() == null || event.getError() != null) {
            return;
        }
        Matcher m = CREDENTIAL_PATH.matcher(event.getResourcePath());
        if (m.matches()) {
            reconcile(event.getRealmId(), m.group(1));
        }
    }

    /** End the sessions verified by a WebAuthn credential the user no longer has; drop approvals of such ids. */
    private void reconcile(String realmId, String userId) {
        RealmModel realm = session.realms().getRealm(realmId);
        UserModel user = realm == null ? null : session.users().getUserById(realm, userId);
        if (user == null) {
            return;
        }
        Set<String> present = Passkeys.credentialIds(user);

        Set<String> approved = user.getAttributeStream(Passkeys.USER_APPROVED)
                .collect(java.util.stream.Collectors.toCollection(java.util.LinkedHashSet::new));
        if (approved.retainAll(present)) {
            Passkeys.setApproved(user, approved);
        }

        List<UserSessionModel> ended = session.sessions().getUserSessionsStream(realm, user)
                .filter(us -> {
                    Set<String> verifiedBy = Passkeys.splitNote(us.getNote(Passkeys.SESSION_VERIFIED_BY));
                    return verifiedBy.stream().anyMatch(id -> !present.contains(id));
                })
                .toList();
        for (UserSessionModel us : ended) {
            LOG.infof("ending session %s of user %s in realm %s: a WebAuthn credential that verified it was deleted",
                    us.getId(), user.getId(), realm.getName());
            try {
                AuthenticationManager.backchannelLogout(session, us, true);
            } catch (RuntimeException e) {
                LOG.warnf(e, "back-channel logout of session %s failed; removing it", us.getId());
                session.sessions().removeUserSession(realm, us);
            }
        }
    }

    @Override
    public void close() {
    }
}
