/*
 * Copyright 2026 Ploutos Services LLC
 * SPDX-License-Identifier: Apache-2.0
 */
package chowkidar.passkey;

import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.browser.WebAuthnAuthenticatorFactory;
import org.keycloak.models.KeycloakSession;

/**
 * "Passkey (approved)": placed in a flow where Keycloak's "WebAuthn Authenticator" would be. Setup during
 * sign-in is not offered: a key enrolled there would verify the very sign-in that enrolled it before anyone
 * approved it. A person enrols a key in the account console; it waits for approval.
 */
public class ApprovedPasskeyAuthenticatorFactory extends WebAuthnAuthenticatorFactory {

    public static final String ID = "chowkidar-passkey-authenticator";

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public String getDisplayType() {
        return "Passkey (approved)";
    }

    @Override
    public String getHelpText() {
        return "WebAuthn second factor that accepts only a credential an administrator has approved, "
                + "and records the credential on the session it verifies.";
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return new ApprovedPasskeyAuthenticator(session);
    }
}
