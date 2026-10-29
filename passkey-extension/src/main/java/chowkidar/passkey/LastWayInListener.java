/*
 * Copyright 2026 Ploutos Services LLC
 * SPDX-License-Identifier: Apache-2.0
 */
package chowkidar.passkey;

import java.util.Map;

import org.keycloak.events.Details;
import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventType;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

/**
 * Records on each person how they last signed in, for {@link AddressRouter}: the broker's alias after a
 * brokered sign-in, {@value #CERTIFICATE} after a certificate sign-in. A sign-in answered by the session alone
 * records nothing (its LOGIN event names neither a broker nor a certificate).
 */
public class LastWayInListener implements EventListenerProvider {

    static final String ATTRIBUTE = "chowkidarLastWayIn";
    static final String CERTIFICATE = "certificate";
    /** Written by {@link AddressRouter} itself after a key sign-in (its LOGIN event names no broker). */
    static final String PASSKEY = "passkey";
    private static final String X509_SUBJECT = "x509_cert_subject_distinguished_name";

    private final KeycloakSession session;

    LastWayInListener(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public void onEvent(Event event) {
        if (event.getType() != EventType.LOGIN || event.getUserId() == null) {
            return;
        }
        Map<String, String> details = event.getDetails() == null ? Map.of() : event.getDetails();
        String way = details.get(Details.IDENTITY_PROVIDER);
        if (way == null && details.containsKey(X509_SUBJECT)) {
            way = CERTIFICATE;
        }
        if (way == null) {
            return;
        }
        RealmModel realm = session.realms().getRealm(event.getRealmId());
        UserModel user = realm == null ? null : session.users().getUserById(realm, event.getUserId());
        if (user != null && !way.equals(user.getFirstAttribute(ATTRIBUTE))) {
            user.setSingleAttribute(ATTRIBUTE, way);
        }
    }

    @Override
    public void onEvent(AdminEvent event, boolean includeRepresentation) {
    }

    @Override
    public void close() {
    }
}
