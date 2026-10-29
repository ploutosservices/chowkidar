/*
 * Copyright 2026 Ploutos Services LLC
 * SPDX-License-Identifier: Apache-2.0
 */
package chowkidar.passkey;

import java.util.List;

import org.keycloak.Config;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticator;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

/** "Condition - level requested": see {@link RequestedLevelCondition}. */
public class RequestedLevelConditionFactory implements ConditionalAuthenticatorFactory {

    public static final String ID = "chowkidar-requested-level";
    private static final RequestedLevelCondition SINGLETON = new RequestedLevelCondition();

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public String getDisplayType() {
        return "Condition - level requested";
    }

    @Override
    public String getHelpText() {
        return "Matches when the application asked (acr_values) for at least the configured level of authentication.";
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        ProviderConfigProperty level = new ProviderConfigProperty();
        level.setName(RequestedLevelCondition.LEVEL);
        level.setLabel("Level");
        level.setType(ProviderConfigProperty.STRING_TYPE);
        level.setHelpText("The level (a number of the realm's acr.loa.map) the application must have asked for.");
        return List.of(level);
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return new AuthenticationExecutionModel.Requirement[] {
                AuthenticationExecutionModel.Requirement.REQUIRED, AuthenticationExecutionModel.Requirement.DISABLED};
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public ConditionalAuthenticator getSingleton() {
        return SINGLETON;
    }

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
    }
}
