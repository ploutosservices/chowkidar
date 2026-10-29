/*
 * Copyright 2026 Ploutos Services LLC
 * SPDX-License-Identifier: Apache-2.0
 */
package chowkidar.passkey;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationProcessor;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.FlowStatus;
import org.keycloak.authentication.authenticators.browser.IdentityProviderAuthenticator;
import org.keycloak.authentication.authenticators.browser.WebAuthnAuthenticator;
import org.keycloak.authentication.authenticators.browser.WebAuthnPasswordlessAuthenticator;
import org.keycloak.authentication.authenticators.util.AcrStore;
import org.keycloak.common.util.Time;
import org.keycloak.credential.CredentialModel;
import org.keycloak.models.Constants;
import org.keycloak.models.FederatedIdentityModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.OTPCredentialModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.protocol.LoginProtocol;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.services.x509.X509ClientCertificateLookup;
import org.keycloak.sessions.AuthenticationSessionModel;

/**
 * Email first: the page asks for the address only, then
 * <ul>
 *   <li>a person holding an enrolled device key, where the realm turns the key on as a way in
 *       ({@value Passkeys#REALM_KEY_SIGN_IN}), is asked for that key — any
 *       enrolled key signs in at silver; an approved, device-bound key touched here reaches gold;</li>
 *   <li>any other address the realm knows goes straight to the way that person last signed in — a broker, or
 *       the certificate (the next step of the flow) — as {@link LastWayInListener} recorded it;</li>
 *   <li>an address it does not know, or a person with no way in to go by, gets the page again with every
 *       option: the realm's brokers and the certificate (a template draws them when {@value #CHOOSE} is set; the
 *       shipped login-username.ftl always draws the broker buttons).</li>
 * </ul>
 * The key page carries "not this way" ({@value #NOT_THIS_WAY}): forget the person, show every way in.
 * The typed address only routes: whoever the broker, the certificate or the key names is who signs in.
 * <p>
 * A PASSKEY AS A WAY IN: "Sign in with a
 * passkey" ({@value #PASSKEY_BUTTON}) runs Keycloak's own passwordless WebAuthn with no person named first, so the browser
 * lists every passkey held for this door and the one chosen names the user. Optional: the providers stay.
 * <p>
 * THE WAY BACK IN: "Lost your way in?" ({@value #LOST}) asks
 * the address plus a code from the authenticator app the person set up earlier; a match signs in at SILVER only,
 * never gold; every failure answers the same page and message; five wrong codes in fifteen minutes stop the check.
 */
public class AddressRouter implements Authenticator {

    private static final Logger LOG = Logger.getLogger(AddressRouter.class);

    static final String CHOOSE = "chowkidarChoose";
    static final String CERTIFICATE_BUTTON = "chowkidar_certificate";
    static final String NOT_THIS_WAY = "chowkidar_not_this_way";
    /** Template attribute: the WebAuthn page is the key as a way in (draws "not this way"). */
    static final String KEY_WAY_IN = "chowkidarKeyWayIn";
    /** Authentication-session note: the key page was served by this router for the user set on the session. */
    static final String KEY_NOTE = "chowkidar.keyWayIn";
    /** The passkey button, and the authentication-session note that the discoverable passkey page was served. */
    static final String PASSKEY_BUTTON = "chowkidar_passkey";
    static final String PASSKEY_NOTE = "chowkidar.passkeyWayIn";
    /** The recovery way in: the form field, the page's template attribute, the throttle's user attribute. */
    static final String LOST = "chowkidar_lost";
    static final String LOST_PAGE = "chowkidarLost";
    static final String FAILURES = "chowkidarRecoveryFailures";
    private static final int FAILURES_ALLOWED = 5;
    private static final long FAILURE_WINDOW_MS = 15 * 60 * 1000L;

    /** Keycloak's redirect to a broker, reached through its protected method. */
    private static final class Redirect extends IdentityProviderAuthenticator {
        void to(AuthenticationFlowContext context, String alias) {
            redirect(context, alias);
        }
    }

    private static final Redirect REDIRECT = new Redirect();

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        context.challenge(form(context).createLoginUsername());
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> form = context.getHttpRequest().getDecodedFormParameters();
        AuthenticationSessionModel auth = context.getAuthenticationSession();
        if (form.containsKey(NOT_THIS_WAY)) {
            auth.removeAuthNote(KEY_NOTE);
            context.clearUser();
            choose(context, new MultivaluedHashMap<>());
            return;
        }
        if (form.containsKey(PASSKEY_BUTTON)) {
            auth.removeAuthNote(KEY_NOTE);
            auth.setAuthNote(PASSKEY_NOTE, "1");
            context.clearUser();
            new WebAuthnPasswordlessAuthenticator(context.getSession()).authenticate(context);
            return;
        }
        if (auth.getAuthNote(PASSKEY_NOTE) != null
                && (form.containsKey("authenticatorData") || form.containsKey("credentialId") || form.containsKey("error"))) {
            auth.removeAuthNote(PASSKEY_NOTE);
            new WebAuthnPasswordlessAuthenticator(context.getSession()).action(context);
            if (context.getStatus() == FlowStatus.SUCCESS && context.getUser() != null) {
                context.getUser().setSingleAttribute(LastWayInListener.ATTRIBUTE, LastWayInListener.PASSKEY);
            }
            return;
        }
        if (form.containsKey(LOST)) {
            recover(context, form);
            return;
        }
        if (auth.getAuthNote(KEY_NOTE) != null && context.getUser() != null
                && (form.containsKey("authenticatorData") || form.containsKey("credentialId") || form.containsKey("error"))) {
            keyAnswered(context, form);
            return;
        }
        auth.removeAuthNote(KEY_NOTE);
        String address = form.getFirst("username");
        KeycloakSession session = context.getSession();
        RealmModel realm = context.getRealm();
        UserModel user = address == null || address.isBlank() ? null
                : KeycloakModelUtils.findUserByNameOrEmail(session, realm, address.trim());
        if (user != null && user.isEnabled() && Passkeys.keySignIn(realm) && !Passkeys.credentialIds(user).isEmpty()) {
            askForKey(context, user);
            return;
        }
        String way = user == null ? null : wayIn(session, realm, user);
        if (way == null) {
            choose(context, form);
        } else if (LastWayInListener.CERTIFICATE.equals(way)) {
            context.attempted();
        } else {
            REDIRECT.to(context, way);
        }
    }

    /** The key page, for this person's enrolled keys (Keycloak's own WebAuthn page, with "not this way"). */
    private static void askForKey(AuthenticationFlowContext context, UserModel user) {
        context.setUser(user);
        context.getAuthenticationSession().setAuthNote(KEY_NOTE, "1");
        WebAuthnAuthenticator key = new WebAuthnAuthenticator(context.getSession());
        context.challenge(key.fillContextForm(context).setAttribute(KEY_WAY_IN, Boolean.TRUE).createLoginWebAuthn());
    }

    /**
     * The key page answered. An application that asked for the higher level gets it only from an approved,
     * device-bound key; any other key is sent back with access_denied before its signature is even
     * checked, as the step-up does. Otherwise Keycloak's own WebAuthn check decides, and on success the session
     * is marked: the level reached (silver, or gold for an approved device-bound key), the key that verified it
     * (deleting that key later ends the session, as PasskeyRevokeListener does), and the person's last way in.
     */
    private static void keyAnswered(AuthenticationFlowContext context, MultivaluedMap<String, String> form) {
        KeycloakSession session = context.getSession();
        RealmModel realm = context.getRealm();
        UserModel user = context.getUser();
        AuthenticationSessionModel auth = context.getAuthenticationSession();
        String error = form.getFirst("error");
        Optional<CredentialModel> used = (error != null && !error.isEmpty())
                ? Optional.empty() : Passkeys.byWebAuthnId(user, form.getFirst("credentialId"));
        boolean gold = used.isPresent() && Passkeys.approved(session, user).contains(used.get().getId())
                && !Passkeys.keptOffGold(session, realm, user, used.get().getId());
        int requested = parse(auth.getClientNote(Constants.REQUESTED_LEVEL_OF_AUTHENTICATION), Constants.NO_LOA);
        if (used.isPresent() && requested >= Passkeys.GOLD && !gold) {
            LOG.infof("key %s of user %s in realm %s cannot reach the requested level %d; back to the application",
                    used.get().getId(), user.getId(), realm.getName(), requested);
            LoginProtocol protocol = session.getProvider(LoginProtocol.class, auth.getProtocol());
            protocol.setRealm(realm).setHttpHeaders(context.getHttpRequest().getHttpHeaders())
                    .setUriInfo(context.getUriInfo()).setEventBuilder(context.getEvent());
            Response back = protocol.sendError(auth, LoginProtocol.Error.CONSENT_DENIED, ApprovedPasskeyAuthenticator.NOT_APPROVED);
            context.forceChallenge(back);
            return;
        }
        new WebAuthnAuthenticator(session).action(context);
        if (used.isEmpty() || !succeeded(context)) {
            return;
        }
        auth.removeAuthNote(KEY_NOTE);
        new AcrStore(session, auth).setLevelAuthenticated(gold ? Passkeys.GOLD : Passkeys.SILVER);
        Set<String> ids = Passkeys.splitNote(auth.getUserSessionNotes().get(Passkeys.SESSION_VERIFIED_BY));
        ids.add(used.get().getId());
        auth.setUserSessionNote(Passkeys.SESSION_VERIFIED_BY, String.join(",", ids));
        if (!LastWayInListener.PASSKEY.equals(user.getFirstAttribute(LastWayInListener.ATTRIBUTE))) {
            user.setSingleAttribute(LastWayInListener.ATTRIBUTE, LastWayInListener.PASSKEY);
        }
    }

    private static boolean succeeded(AuthenticationFlowContext context) {
        return context instanceof AuthenticationProcessor.Result result && result.getStatus() == FlowStatus.SUCCESS;
    }

    private static long parseLong(String s) {
        try {
            return s == null ? 0L : Long.parseLong(s.trim());
        } catch (NumberFormatException e) {
            return 0L;
        }
    }

    private static int parse(String s, int otherwise) {
        try {
            return s == null ? otherwise : Integer.parseInt(s.trim());
        } catch (NumberFormatException e) {
            return otherwise;
        }
    }

    /**
     * The way back in. Order: forget any person the key page set; refuse an application that
     * asked for gold, for every address, before any lookup; no code yet -> the recovery page; then the person (by
     * name or email, enabled, holding an authenticator app), the throttle, and Keycloak's own OTP check per stored
     * credential (its policy, look-ahead and reuse protection). Every failure is the same page and message.
     */
    private static void recover(AuthenticationFlowContext context, MultivaluedMap<String, String> form) {
        AuthenticationSessionModel auth = context.getAuthenticationSession();
        auth.removeAuthNote(KEY_NOTE);
        context.clearUser();
        int requested = parse(auth.getClientNote(Constants.REQUESTED_LEVEL_OF_AUTHENTICATION), Constants.NO_LOA);
        if (requested >= Passkeys.GOLD) {
            LOG.infof("recovery cannot reach the requested level %d in realm %s; back to the application",
                    requested, context.getRealm().getName());
            backToApplication(context);
            return;
        }
        String code = form.getFirst("otp");
        if (code == null || code.isBlank()) {
            lostPage(context, form, false);
            return;
        }
        String address = form.getFirst("username");
        KeycloakSession session = context.getSession();
        RealmModel realm = context.getRealm();
        UserModel user = address == null || address.isBlank() ? null
                : KeycloakModelUtils.findUserByNameOrEmail(session, realm, address.trim());
        List<CredentialModel> apps = user == null || !user.isEnabled() ? List.of()
                : user.credentialManager().getStoredCredentialsByTypeStream(OTPCredentialModel.TYPE).toList();
        if (apps.isEmpty()) {
            lostPage(context, form, true);
            return;
        }
        // MILLISECONDS, not seconds: Keycloak keeps an attribute's values as a set, so two wrong codes in one
        // second would collapse into one entry and the throttle would never reach five.
        long now = Time.currentTimeMillis();
        List<String> recent = new ArrayList<>(user.getAttributeStream(FAILURES)
                .filter(t -> parseLong(t) > now - FAILURE_WINDOW_MS).toList());
        if (recent.size() >= FAILURES_ALLOWED) {
            LOG.infof("recovery throttled for user %s in realm %s", user.getId(), realm.getName());
            lostPage(context, form, true);
            return;
        }
        String typed = code.trim();
        boolean match = apps.stream().anyMatch(c -> user.credentialManager()
                .isValid(new UserCredentialModel(c.getId(), OTPCredentialModel.TYPE, typed)));
        if (!match) {
            recent.add(Long.toString(now));
            user.setAttribute(FAILURES, recent);
            lostPage(context, form, true);
            return;
        }
        user.removeAttribute(FAILURES);
        context.setUser(user);
        new AcrStore(session, auth).setLevelAuthenticated(Passkeys.SILVER);
        context.getEvent().detail("chowkidar_recovered", "1");
        LOG.infof("recovery sign-in of user %s in realm %s", user.getId(), realm.getName());
        context.success();
    }

    /** The recovery page: the address kept, the code asked, "Back"; with the one neutral message on a failure. */
    private static void lostPage(AuthenticationFlowContext context, MultivaluedMap<String, String> form, boolean failed) {
        MultivaluedMap<String, String> kept = new MultivaluedHashMap<>();
        String address = form.getFirst("username");
        if (address != null) {
            kept.putSingle("username", address);
        }
        var page = form(context).setFormData(kept).setAttribute(LOST_PAGE, Boolean.TRUE);
        if (failed) {
            page.setError("chowkidarRecoveryNoMatch");
        }
        context.challenge(page.createLoginUsername());
    }

    /** access_denied back to the application with the "not approved" reason — the key page's refusal shape. */
    private static void backToApplication(AuthenticationFlowContext context) {
        KeycloakSession session = context.getSession();
        AuthenticationSessionModel auth = context.getAuthenticationSession();
        LoginProtocol protocol = session.getProvider(LoginProtocol.class, auth.getProtocol());
        protocol.setRealm(context.getRealm()).setHttpHeaders(context.getHttpRequest().getHttpHeaders())
                .setUriInfo(context.getUriInfo()).setEventBuilder(context.getEvent());
        Response back = protocol.sendError(auth, LoginProtocol.Error.CONSENT_DENIED, ApprovedPasskeyAuthenticator.NOT_APPROVED);
        context.forceChallenge(back);
    }

    /** The recorded way in when it still exists; else the person's only broker; else the certificate. */
    static String wayIn(KeycloakSession session, RealmModel realm, UserModel user) {
        List<String> links = session.users().getFederatedIdentitiesStream(realm, user)
                .map(FederatedIdentityModel::getIdentityProvider).toList();
        String last = user.getFirstAttribute(LastWayInListener.ATTRIBUTE);
        if (LastWayInListener.CERTIFICATE.equals(last) || (last != null && links.contains(last))) {
            return last;
        }
        if (links.size() == 1) {
            return links.get(0);
        }
        return links.isEmpty() ? LastWayInListener.CERTIFICATE : null;
    }

    /** The page's form, with the door's act-as console address when the browser presented a valid certificate on this
     *  request (a button on the page, never an address to remember). Act-as itself is still decided
     *  by the console's own permissions. */
    static final String CONSOLE = "chowkidarConsole";

    /** Why the application sent the person here, from a FIXED list: the door shows its own words for each code and never
     *  text an application sends (for example "you are logged out, log back in" or "we needed a certificate").
     *  The application adds chowkidar_reason=<code> to its authorization request; Keycloak keeps an unknown request
     *  parameter as the client note client_request_param_<name>. */
    static final String REASON = "chowkidarReason";
    static final Set<String> REASONS = Set.of("signed_out", "certificate_needed", "session_expired", "sign_in_again");

    private static LoginFormsProvider form(AuthenticationFlowContext context) {
        LoginFormsProvider page = context.form();
        String reason = context.getAuthenticationSession().getClientNote("client_request_param_chowkidar_reason");
        if (reason != null && REASONS.contains(reason)) {
            page.setAttribute(REASON, reason);
        }
        try {
            X509ClientCertificateLookup lookup = context.getSession().getProvider(X509ClientCertificateLookup.class);
            X509Certificate[] chain = lookup == null ? null : lookup.getCertificateChain(context.getHttpRequest());
            if (chain != null && chain.length > 0) {
                chain[0].checkValidity();
                page.setAttribute(CONSOLE, context.getUriInfo().getBaseUri().toString().replaceAll("/+$", "")
                        + "/admin/" + context.getRealm().getName() + "/console/");
            }
        } catch (Exception e) {
            // no certificate, or not valid now: no button
        }
        return page;
    }

    private static void choose(AuthenticationFlowContext context, MultivaluedMap<String, String> form) {
        Response page = form(context).setFormData(form).setAttribute(CHOOSE, Boolean.TRUE)
                .setInfo("chowkidarChooseHow").createLoginUsername();
        context.challenge(page);
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    }

    @Override
    public void close() {
    }
}
