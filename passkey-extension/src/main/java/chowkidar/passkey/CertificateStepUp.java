/*
 * Copyright 2026 Ploutos Services LLC
 * SPDX-License-Identifier: Apache-2.0
 */
package chowkidar.passkey;

import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.protocol.LoginProtocol;
import org.keycloak.services.x509.X509ClientCertificateLookup;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.truststore.TruststoreProvider;

/**
 * The step-up to a higher level by the person's device CERTIFICATE, on the session the person already has (the door tells an app "more about my certificate" when it asks, and never merges accounts).
 * <ul>
 *   <li>It never changes the user: a session signed in as one account stays that account. Keycloak's own X.509
 *       authenticator maps the certificate to a user and would switch it; this one only checks the certificate.</li>
 *   <li>The certificate must come with the request (the nginx lookup), be valid now, be signed by a CA in the door's
 *       truststore, and its subject must match the configured regular expression.</li>
 *   <li>The certificate must be one of THIS user's machines: its CN is a value of the user's {@value #MACHINES}
 *       attribute (the certificate is a machine, never a user; the standard binding of a certificate
 *       to the account, with no second account).</li>
 *   <li>Its subject is recorded on the session ({@value #NOTE}), so the token can carry it.</li>
 *   <li>No certificate, or one that fails: back to the application with access_denied, never a door error page.</li>
 * </ul>
 * The level itself is set by the Condition - Level of Authentication of the sub-flow this step sits in.
 */
public class CertificateStepUp implements Authenticator {

    private static final Logger LOG = Logger.getLogger(CertificateStepUp.class);
    static final String NOTE = "certificate_subject";
    static final String REGEX = "subject_regex";
    static final String MACHINES = "chowkidarMachines";
    static final String MISSING = "chowkidar_certificate_required";
    static final String REFUSED = "chowkidar_certificate_refused";

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        UserModel user = context.getUser();
        X509Certificate cert;
        try {
            X509ClientCertificateLookup lookup = context.getSession().getProvider(X509ClientCertificateLookup.class);
            X509Certificate[] chain = lookup == null ? null : lookup.getCertificateChain(context.getHttpRequest());
            cert = chain == null || chain.length == 0 ? null : chain[0];
        } catch (Exception e) {
            cert = null;
        }
        if (user == null || cert == null) {
            LOG.infof("certificate step-up in realm %s: no certificate came with the request", context.getRealm().getName());
            sendBack(context, MISSING);
            return;
        }
        String subject = cert.getSubjectX500Principal().getName();
        String why = refusal(context, cert, subject);
        if (why == null && !user.getAttributeStream(MACHINES).anyMatch(commonName(cert)::equals)) {
            why = "not one of this user's machines";
        }
        if (why != null) {
            LOG.infof("certificate step-up in realm %s refused for user %s: %s", context.getRealm().getName(), user.getId(), why);
            sendBack(context, REFUSED);
            return;
        }
        context.getAuthenticationSession().setUserSessionNote(NOTE, subject);
        LOG.infof("certificate step-up in realm %s: user %s presented %s", context.getRealm().getName(), user.getId(), subject);
        context.success();
    }

    /** Why the certificate is refused, or null when it passes. */
    private static String refusal(AuthenticationFlowContext context, X509Certificate cert, String subject) {
        try {
            cert.checkValidity();
        } catch (Exception e) {
            return "not valid now";
        }
        AuthenticatorConfigModel cfg = context.getAuthenticatorConfig();
        String regex = cfg == null || cfg.getConfig() == null ? null : cfg.getConfig().get(REGEX);
        if (regex == null || regex.isBlank()) {
            return "no subject_regex configured";
        }
        Matcher m = Pattern.compile(regex).matcher(subject);
        if (!m.find()) {
            return "subject does not match";
        }
        if (!issuedByTrusted(context.getSession(), cert)) {
            return "not signed by a CA the door trusts";
        }
        return null;
    }

    /** The subject's CN (the machine's name, CN=<person>-<machine>@<environment>), or "" when it has none. */
    private static String commonName(X509Certificate cert) {
        try {
            for (javax.naming.ldap.Rdn rdn : new javax.naming.ldap.LdapName(cert.getSubjectX500Principal().getName()).getRdns()) {
                if ("CN".equalsIgnoreCase(rdn.getType())) {
                    return rdn.getValue().toString();
                }
            }
        } catch (Exception e) {
            // no CN
        }
        return "";
    }

    private static boolean issuedByTrusted(KeycloakSession session, X509Certificate cert) { // gitleaks:allow (a parameter list, not a key)
        TruststoreProvider ts = session.getProvider(TruststoreProvider.class);
        KeyStore store = ts == null ? null : ts.getTruststore();
        if (store == null) {
            return false;
        }
        try {
            for (String alias : Collections.list(store.aliases())) {
                Certificate c = store.getCertificate(alias);
                if (c instanceof X509Certificate ca && ca.getSubjectX500Principal().equals(cert.getIssuerX500Principal())) {
                    try {
                        ca.checkValidity();
                        cert.verify(ca.getPublicKey());
                        return true;
                    } catch (Exception e) {
                        // try the next CA of the same name
                    }
                }
            }
        } catch (Exception e) {
            return false;
        }
        return false;
    }

    /** Back to the application with an OAuth error (access_denied, the description naming why). */
    private static void sendBack(AuthenticationFlowContext context, String reason) {
        AuthenticationSessionModel auth = context.getAuthenticationSession();
        KeycloakSession session = context.getSession();
        LoginProtocol protocol = session.getProvider(LoginProtocol.class, auth.getProtocol());
        protocol.setRealm(context.getRealm()).setHttpHeaders(context.getHttpRequest().getHttpHeaders())
                .setUriInfo(context.getUriInfo()).setEventBuilder(context.getEvent());
        context.forceChallenge(protocol.sendError(auth, LoginProtocol.Error.CONSENT_DENIED, reason));
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        authenticate(context);
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
