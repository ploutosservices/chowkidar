/*
 * Copyright 2026 Ploutos Services LLC
 * SPDX-License-Identifier: Apache-2.0
 */
package chowkidar.passkey;

import org.keycloak.Config;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventListenerProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

/** Event listener "chowkidar-last-way-in", enabled per realm: see {@link LastWayInListener}. */
public class LastWayInListenerFactory implements EventListenerProviderFactory {

    public static final String ID = "chowkidar-last-way-in";

    @Override
    public EventListenerProvider create(KeycloakSession session) {
        return new LastWayInListener(session);
    }

    @Override
    public String getId() {
        return ID;
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
