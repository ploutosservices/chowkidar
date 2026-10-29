/*
 * Copyright 2026 Ploutos Services LLC
 * SPDX-License-Identifier: Apache-2.0
 */
package chowkidar.passkey;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;

import java.net.URI;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.authenticators.browser.IdentityProviderAuthenticator;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.managers.AuthenticationManager;

/**
 * Keycloak's "Identity Provider Redirector", with one addition: when the application's hint names a broker the
 * person signed in at the door is NOT linked to, that door session is ended and the same authorization request
 * starts again without it, so the browser goes to the broker with no one signed in. Keycloak would otherwise refuse whoever the broker returns ("already authenticated as different user"),
 * because a browser holds one person per realm. A hint naming a broker the person IS linked to keeps the session.
 *
 * The person is ASKED first (a signed-in person never sees a login screen; the other button asks
 * "switch?"): a page names who is signed in and the account asked for, with Switch and Stay. Switch ends the session
 * as above; Stay returns the person to the application signed in as they are.
 */
public class SwitchingBrokerRedirector extends IdentityProviderAuthenticator {

    private static final Logger LOG = Logger.getLogger(SwitchingBrokerRedirector.class);
    static final String HINT = "kc_idp_hint";
    static final String RESTART = "chowkidar.switch.restart";
    static final String CHOICE = "chowkidar_switch";

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        String hint = context.getUriInfo().getQueryParameters().getFirst(HINT);
        if (hint != null && !hint.isBlank()) {
            KeycloakSession session = context.getSession();
            RealmModel realm = context.getRealm();
            AuthenticationManager.AuthResult current = AuthenticationManager.authenticateIdentityCookie(session, realm, true);
            if (current != null && current.getUser() != null && !linked(session, realm, current.getUser(), hint)) {
                context.getAuthenticationSession().setAuthNote(RESTART, context.getUriInfo().getRequestUri().toString());
                IdentityProviderModel idp = session.identityProviders().getByAlias(hint);
                String to = idp != null && idp.getDisplayName() != null && !idp.getDisplayName().isBlank() ? idp.getDisplayName() : hint;
                String from = current.getUser().getEmail() != null ? current.getUser().getEmail() : current.getUser().getUsername();
                context.challenge(context.form()
                        .setAttribute("chowkidarSwitchTo", to)
                        .setAttribute("chowkidarSwitchFrom", from)
                        .createForm("chowkidar-switch-account.ftl"));
                return;
            }
        }
        super.authenticate(context);
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        KeycloakSession session = context.getSession();
        RealmModel realm = context.getRealm();
        MultivaluedMap<String, String> form = context.getHttpRequest().getDecodedFormParameters();
        AuthenticationManager.AuthResult current = AuthenticationManager.authenticateIdentityCookie(session, realm, true);
        String restart = context.getAuthenticationSession().getAuthNote(RESTART);
        if (current == null || current.getUser() == null) {
            context.attempted();
            return;
        }
        if ("switch".equals(form.getFirst(CHOICE)) && restart != null) {
            LOG.infof("ending door session %s of user %s in realm %s: the person chose to switch to another account",
                    current.getSession().getId(), current.getUser().getId(), realm.getName());
            // The sign-in in progress lives in the old session's authentication session, and Keycloak ties
            // the broker's answer to that person whatever is cleared here. So the old session
            // ends, its cookies go, and the browser asks the SAME authorization request again, from nothing.
            AuthenticationManager.backchannelLogout(session, current.getSession(), true);
            AuthenticationManager.expireIdentityCookie(session);
            AuthenticationManager.expireAuthSessionCookie(session);
            context.forceChallenge(Response.seeOther(URI.create(restart)).build());
            return;
        }
        // Stay: back to the application as the person already signed in, as the cookie step would.
        context.setUser(current.getUser());
        context.attachUserSession(current.getSession());
        context.success();
    }

    private static boolean linked(KeycloakSession session, RealmModel realm, UserModel user, String broker) {
        return session.users().getFederatedIdentitiesStream(realm, user)
                .anyMatch(f -> broker.equals(f.getIdentityProvider()));
    }
}
