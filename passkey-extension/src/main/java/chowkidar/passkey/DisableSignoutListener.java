/*
 * Copyright 2026 Ploutos Services LLC
 * SPDX-License-Identifier: Apache-2.0
 */
package chowkidar.passkey;

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.jboss.logging.Logger;
import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.events.admin.OperationType;
import org.keycloak.events.admin.ResourceType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.services.managers.AuthenticationManager;

/**
 * Disabling a user ends that user's sessions: when an administrator disables a user, every
 * session that user holds is ended through back-channel logout, so each application holding one is told
 * (at its back-channel logout address) and ends its own. Keycloak 26.4.4 alone does not: a user disabled by
 * PUT /admin/realms/<realm>/users/{id} {enabled:false} keeps the application session it signed in, and
 * no logout_token is sent. Creation needs no signal: an application creates its user from the claims at
 * first sign-in. Enabled per realm by listing this listener in the realm's event listeners; it reacts to
 * admin events, so the realm must have admin events enabled.
 */
public class DisableSignoutListener implements EventListenerProvider {

    private static final Logger LOG = Logger.getLogger(DisableSignoutListener.class);
    private static final Pattern USER_PATH = Pattern.compile("^users/([^/]+)/?$");

    private final KeycloakSession session;

    DisableSignoutListener(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public void onEvent(Event event) {
    }

    @Override
    public void onEvent(AdminEvent event, boolean includeRepresentation) {
        if (event.getOperationType() != OperationType.UPDATE || event.getResourceType() != ResourceType.USER
                || event.getResourcePath() == null || event.getError() != null) {
            return;
        }
        Matcher m = USER_PATH.matcher(event.getResourcePath());
        if (!m.matches()) {
            return;
        }
        RealmModel realm = session.realms().getRealm(event.getRealmId());
        UserModel user = realm == null ? null : session.users().getUserById(realm, m.group(1));
        if (user == null || user.isEnabled()) {
            return;
        }
        List<UserSessionModel> sessions = session.sessions().getUserSessionsStream(realm, user).toList();
        for (UserSessionModel us : sessions) {
            LOG.infof("ending session %s of user %s in realm %s: the user was disabled", us.getId(), user.getId(), realm.getName());
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
