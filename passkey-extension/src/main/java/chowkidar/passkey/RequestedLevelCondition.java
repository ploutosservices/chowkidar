/*
 * Copyright 2026 Ploutos Services LLC
 * SPDX-License-Identifier: Apache-2.0
 */
package chowkidar.passkey;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticator;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

/**
 * Matches only when the application asked for at least the configured level (acr_values, mapped through the
 * realm's acr.loa.map onto the authentication session). Keycloak's own 'Condition - Level of Authentication'
 * answers "is this level still to be reached", which in a broker's post-login flow is always yes; this one
 * answers "was this level asked for", so a step after the broker runs only on the requested level.
 */
public class RequestedLevelCondition implements ConditionalAuthenticator {

    static final String LEVEL = "level";

    @Override
    public boolean matchCondition(AuthenticationFlowContext context) {
        AuthenticatorConfigModel config = context.getAuthenticatorConfig();
        int wanted = parse(config == null ? null : config.getConfig().get(LEVEL), Integer.MAX_VALUE);
        int requested = parse(context.getAuthenticationSession().getClientNote(Constants.REQUESTED_LEVEL_OF_AUTHENTICATION),
                Constants.NO_LOA);
        return requested >= wanted;
    }

    private static int parse(String s, int otherwise) {
        try {
            return s == null ? otherwise : Integer.parseInt(s.trim());
        } catch (NumberFormatException e) {
            return otherwise;
        }
    }

    @Override
    public void action(AuthenticationFlowContext context) {
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    }

    @Override
    public void close() {
    }
}
