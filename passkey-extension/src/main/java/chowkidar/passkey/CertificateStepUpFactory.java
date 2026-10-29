/*
 * Copyright 2026 Ploutos Services LLC
 * SPDX-License-Identifier: Apache-2.0
 */
package chowkidar.passkey;

import java.util.List;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

/** "Certificate step-up (keeps the user)": see {@link CertificateStepUp}. */
public class CertificateStepUpFactory implements AuthenticatorFactory {

    public static final String ID = "chowkidar-certificate-step-up";
    private static final CertificateStepUp SINGLETON = new CertificateStepUp();

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public String getDisplayType() {
        return "Certificate step-up (keeps the user)";
    }

    @Override
    public String getReferenceCategory() {
        return "certificate";
    }

    @Override
    public String getHelpText() {
        return "Raises the level of the person's existing session when a valid, trusted certificate whose subject matches "
                + "comes with the request; records the subject on the session; never changes the user.";
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        ProviderConfigProperty regex = new ProviderConfigProperty();
        regex.setName(CertificateStepUp.REGEX);
        regex.setLabel("Subject regular expression");
        regex.setType(ProviderConfigProperty.STRING_TYPE);
        regex.setHelpText("A certificate whose subject DN does not match is refused.");
        return List.of(regex);
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
    public Authenticator create(KeycloakSession session) {
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
