/*
 * Copyright 2026 Ploutos Services LLC
 * SPDX-License-Identifier: Apache-2.0
 */
package chowkidar.passkey;

import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.AuthenticationProcessor;
import org.keycloak.authentication.FlowStatus;
import org.keycloak.authentication.authenticators.browser.WebAuthnAuthenticator;
import org.keycloak.credential.CredentialModel;
import org.keycloak.events.Details;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.LoginProtocol;
import org.keycloak.sessions.AuthenticationSessionModel;

/**
 * Keycloak's WebAuthn (second-factor) authenticator, with two additions:
 * <ul>
 *   <li>a credential an administrator has not approved is refused, even when its signature is good;</li>
 *   <li>the credential that verified the session is recorded on it ({@value Passkeys#SESSION_VERIFIED_BY}),
 *       so deleting that credential can end exactly the sessions it verified;</li>
 *   <li>a person holding no approved credential is sent back to the application with an OAuth error
 *       (access_denied, the description naming why), not left on a sign-in page the application never
 *       hears from.</li>
 * </ul>
 */
public class ApprovedPasskeyAuthenticator extends WebAuthnAuthenticator {

    private static final Logger LOG = Logger.getLogger(ApprovedPasskeyAuthenticator.class);

    public ApprovedPasskeyAuthenticator(KeycloakSession session) {
        super(session);
    }

    /** Asked of every person, so one with no key reaches {@link #authenticate} and is answered there. */
    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        UserModel user = context.getUser();
        Set<String> stored = Passkeys.credentialIds(user);
        Set<String> usable = new HashSet<>(Passkeys.approved(session, user));
        usable.retainAll(stored);
        if (Passkeys.refuseBackupEligible(context.getRealm())) {
            usable.removeAll(Passkeys.backupEligible(session, user));   // a synced key never reaches gold
        }
        if (usable.isEmpty()) {
            String reason = stored.isEmpty() ? NO_PASSKEY : NOT_APPROVED;
            LOG.infof("sent user %s of realm %s back to the application: %s", user.getId(), context.getRealm().getName(), reason);
            sendBack(context, reason);
            return;
        }
        super.authenticate(context);
    }

    /** Back to the application's login with an OAuth error (access_denied, the description naming why), never a door
     *  error page (no key -> back on the login page with the error message). */
    private void sendBack(AuthenticationFlowContext context, String reason) {
        AuthenticationSessionModel auth = context.getAuthenticationSession();
        LoginProtocol protocol = session.getProvider(LoginProtocol.class, auth.getProtocol());
        protocol.setRealm(context.getRealm()).setHttpHeaders(context.getHttpRequest().getHttpHeaders())
                .setUriInfo(context.getUriInfo()).setEventBuilder(context.getEvent());
        context.forceChallenge(protocol.sendError(auth, LoginProtocol.Error.CONSENT_DENIED, reason));
    }

    /** error_description values an application can act on (access_denied in OIDC). */
    static final String NO_PASSKEY = "chowkidar_passkey_required";
    static final String NOT_APPROVED = "chowkidar_passkey_not_approved";
    static final String NO_KEY_GIVEN = "chowkidar_passkey_not_given";
    static final String KEY_FAILED = "chowkidar_passkey_failed";

    @Override
    public void action(AuthenticationFlowContext context) {
        UserModel user = context.getUser();
        MultivaluedMap<String, String> form = context.getHttpRequest().getDecodedFormParameters();
        String error = form.getFirst("error");
        if (user == null || (error != null && !error.isEmpty())) {
            LOG.infof("sent a person of realm %s back to the application: no key was given (%s)", context.getRealm().getName(), error);
            sendBack(context, NO_KEY_GIVEN);
            return;
        }
        Optional<CredentialModel> used = Passkeys.byWebAuthnId(user, form.getFirst("credentialId"));

        if (used.isPresent() && (!Passkeys.approved(session, user).contains(used.get().getId())
                || Passkeys.keptOffGold(session, context.getRealm(), user, used.get().getId()))) {
            LOG.infof("refused an unapproved WebAuthn credential %s of user %s in realm %s",
                    used.get().getId(), user.getId(), context.getRealm().getName());
            context.getEvent().detail(Details.CREDENTIAL_TYPE, getCredentialType())
                    .detail(Details.CREDENTIAL_ID, used.get().getId())
                    .detail(Details.REASON, "passkey not approved");
            sendBack(context, NOT_APPROVED);
            return;
        }

        super.action(context);
        if (!succeeded(context)) {
            LOG.infof("sent user %s of realm %s back to the application: the key did not verify", user.getId(), context.getRealm().getName());
            sendBack(context, KEY_FAILED);
            return;
        }

        if (used.isPresent() && succeeded(context)) {
            AuthenticationSessionModel auth = context.getAuthenticationSession();
            Set<String> ids = Passkeys.splitNote(existingNote(context));
            ids.addAll(Passkeys.splitNote(auth.getUserSessionNotes().get(Passkeys.SESSION_VERIFIED_BY)));
            ids.add(used.get().getId());
            auth.setUserSessionNote(Passkeys.SESSION_VERIFIED_BY, String.join(",", ids));
        }
    }

    /** The note already on the user session this sign-in steps up, if there is one. */
    private String existingNote(AuthenticationFlowContext context) {
        AuthenticationSessionModel auth = context.getAuthenticationSession();
        if (auth.getParentSession() == null) {
            return null;
        }
        UserSessionModel existing = session.sessions().getUserSession(context.getRealm(), auth.getParentSession().getId());
        return existing == null ? null : existing.getNote(Passkeys.SESSION_VERIFIED_BY);
    }

    private static boolean succeeded(AuthenticationFlowContext context) {
        return context instanceof AuthenticationProcessor.Result result && result.getStatus() == FlowStatus.SUCCESS;
    }
}
