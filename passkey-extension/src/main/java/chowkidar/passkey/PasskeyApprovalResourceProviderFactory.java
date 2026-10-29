/*
 * Copyright 2026 Ploutos Services LLC
 * SPDX-License-Identifier: Apache-2.0
 */
package chowkidar.passkey;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.services.resources.admin.AdminEventBuilder;
import org.keycloak.services.resources.admin.ext.AdminRealmResourceProvider;
import org.keycloak.services.resources.admin.ext.AdminRealmResourceProviderFactory;
import org.keycloak.services.resources.admin.fgap.AdminPermissionEvaluator;

/** Mounts {@link PasskeyApprovalResource} at /admin/realms/{realm}/chowkidar-passkeys. */
public class PasskeyApprovalResourceProviderFactory implements AdminRealmResourceProviderFactory, AdminRealmResourceProvider {

    public static final String ID = "chowkidar-passkeys";

    @Override
    public AdminRealmResourceProvider create(KeycloakSession session) {
        return this;
    }

    @Override
    public Object getResource(KeycloakSession session, RealmModel realm, AdminPermissionEvaluator auth, AdminEventBuilder adminEvent) {
        return new PasskeyApprovalResource(session, realm, auth, adminEvent);
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

    @Override
    public String getId() {
        return ID;
    }
}
