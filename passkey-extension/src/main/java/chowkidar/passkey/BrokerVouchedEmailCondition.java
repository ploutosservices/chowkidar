/*
 * Copyright 2026 Ploutos Services LLC
 * SPDX-License-Identifier: Apache-2.0
 */
package chowkidar.passkey;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.authenticators.broker.AbstractIdpAuthenticator;
import org.keycloak.authentication.authenticators.broker.util.SerializedBrokeredIdentityContext;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticator;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

/**
 * In a first broker login: matches when the upstream VOUCHED for the address it sent. The vouching is a claim the
 * broker's attribute mapper copied onto the brokered identity (configured name, default {@code xms_edov}, Microsoft
 * Entra's "email domain owner verified"); it matches only on the value {@code true} (or {@code 1}). Absent, false or
 * anything else does not match. With {@code negate} the answer is inverted, so one flow can hold the vouched branch
 * (link by email) and the not-vouched branch (Keycloak's own confirm-and-verify) side by side.
 * Nothing site-specific is in the code: the claim's name is the execution's configuration.
 */
public class BrokerVouchedEmailCondition implements ConditionalAuthenticator {

    static final String ATTRIBUTE = "attribute";
    static final String NEGATE = "negate";
    static final String DEFAULT_ATTRIBUTE = "xms_edov";

    @Override
    public boolean matchCondition(AuthenticationFlowContext context) {
        AuthenticatorConfigModel config = context.getAuthenticatorConfig();
        String name = config == null ? null : config.getConfig().get(ATTRIBUTE);
        if (name == null || name.isBlank()) name = DEFAULT_ATTRIBUTE;
        boolean negate = config != null && Boolean.parseBoolean(config.getConfig().get(NEGATE));
        SerializedBrokeredIdentityContext brokered = SerializedBrokeredIdentityContext.readFromAuthenticationSession(
                context.getAuthenticationSession(), AbstractIdpAuthenticator.BROKERED_CONTEXT_NOTE);
        String value = brokered == null ? null : brokered.getFirstAttribute(name.trim());
        boolean vouched = value != null && ("true".equalsIgnoreCase(value.trim()) || "1".equals(value.trim()));
        return negate != vouched;
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
