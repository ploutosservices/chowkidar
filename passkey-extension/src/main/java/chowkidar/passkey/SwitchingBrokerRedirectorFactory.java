/*
 * Copyright 2026 Ploutos Services LLC
 * SPDX-License-Identifier: Apache-2.0
 */
package chowkidar.passkey;

import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.browser.IdentityProviderAuthenticatorFactory;
import org.keycloak.models.KeycloakSession;

/** "Identity Provider Redirector (switching)": see {@link SwitchingBrokerRedirector}. */
public class SwitchingBrokerRedirectorFactory extends IdentityProviderAuthenticatorFactory {

    public static final String ID = "chowkidar-switching-redirector";
    private static final SwitchingBrokerRedirector SINGLETON = new SwitchingBrokerRedirector();

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public String getDisplayType() {
        return "Identity Provider Redirector (switching)";
    }

    @Override
    public String getHelpText() {
        return "Redirects to the hinted identity provider; when the person signed in is not linked to it, ends that "
                + "session first, so the provider's answer can sign in another person.";
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return SINGLETON;
    }
}
