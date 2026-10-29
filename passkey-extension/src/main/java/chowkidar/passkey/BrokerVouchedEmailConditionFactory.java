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

/** "Condition - upstream vouched for the email": see {@link BrokerVouchedEmailCondition}. */
public class BrokerVouchedEmailConditionFactory implements ConditionalAuthenticatorFactory {

    public static final String ID = "chowkidar-broker-email-vouched";
    private static final BrokerVouchedEmailCondition SINGLETON = new BrokerVouchedEmailCondition();

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public String getDisplayType() {
        return "Condition - upstream vouched for the email";
    }

    @Override
    public String getHelpText() {
        return "In a first broker login, matches when the brokered identity carries the configured attribute with the value true.";
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        ProviderConfigProperty attribute = new ProviderConfigProperty();
        attribute.setName(BrokerVouchedEmailCondition.ATTRIBUTE);
        attribute.setLabel("Attribute");
        attribute.setType(ProviderConfigProperty.STRING_TYPE);
        attribute.setDefaultValue(BrokerVouchedEmailCondition.DEFAULT_ATTRIBUTE);
        attribute.setHelpText("The brokered identity's attribute (set by the broker's attribute importer) that says the upstream vouched for the address.");
        ProviderConfigProperty negate = new ProviderConfigProperty();
        negate.setName(BrokerVouchedEmailCondition.NEGATE);
        negate.setLabel("Negate");
        negate.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        negate.setHelpText("Match when the upstream did NOT vouch.");
        return List.of(attribute, negate);
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
