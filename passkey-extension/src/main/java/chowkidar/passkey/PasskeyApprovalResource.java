/*
 * Copyright 2026 Ploutos Services LLC
 * SPDX-License-Identifier: Apache-2.0
 */
package chowkidar.passkey;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.keycloak.credential.CredentialModel;
import org.keycloak.events.admin.OperationType;
import org.keycloak.events.admin.ResourceType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.resources.admin.AdminEventBuilder;
import org.keycloak.services.resources.admin.fgap.AdminPermissionEvaluator;

/**
 * The administrator's approval of a WebAuthn credential, under the admin API:
 * <pre>
 *   GET    /admin/realms/{realm}/chowkidar-passkeys/pending
 *   GET    /admin/realms/{realm}/chowkidar-passkeys/users/{userId}
 *   PUT    /admin/realms/{realm}/chowkidar-passkeys/users/{userId}/credentials/{credentialId}/approval
 *   DELETE /admin/realms/{realm}/chowkidar-passkeys/users/{userId}/credentials/{credentialId}/approval
 * </pre>
 * Reading needs view-users; approving needs manage-users on that user. Who holds those is configuration.
 * Each approval is an admin event.
 */
public class PasskeyApprovalResource {

    private final KeycloakSession session;
    private final RealmModel realm;
    private final AdminPermissionEvaluator auth;
    private final AdminEventBuilder adminEvent;

    PasskeyApprovalResource(KeycloakSession session, RealmModel realm, AdminPermissionEvaluator auth, AdminEventBuilder adminEvent) {
        this.session = session;
        this.realm = realm;
        this.auth = auth;
        this.adminEvent = adminEvent.resource(ResourceType.USER);
    }

    @GET
    @Path("pending")
    @Produces(MediaType.APPLICATION_JSON)
    public List<Map<String, Object>> pending() {
        auth.users().requireView();
        List<Map<String, Object>> out = new ArrayList<>();
        session.users().searchForUserStream(realm, new HashMap<>()).forEach(user -> {
            Set<String> approved = Passkeys.approved(session, user);
            user.credentialManager().getStoredCredentialsByTypeStream(Passkeys.TYPE)
                    .filter(c -> !approved.contains(c.getId()))
                    .forEach(c -> {
                        Map<String, Object> row = row(c, false);
                        row.put("backupEligible", Passkeys.backupEligible(session, user).contains(c.getId()));
                        row.put("userId", user.getId());
                        row.put("username", user.getUsername());
                        out.add(row);
                    });
        });
        return out;
    }

    @GET
    @Path("users/{userId}")
    @Produces(MediaType.APPLICATION_JSON)
    public List<Map<String, Object>> credentials(@PathParam("userId") String userId) {
        UserModel user = user(userId);
        auth.users().requireView(user);
        Set<String> approved = Passkeys.approved(session, user);
        Set<String> synced = Passkeys.backupEligible(session, user);
        return user.credentialManager().getStoredCredentialsByTypeStream(Passkeys.TYPE)
                .map(c -> {
                    Map<String, Object> row = row(c, approved.contains(c.getId()));
                    row.put("backupEligible", synced.contains(c.getId()));
                    return row;
                }).toList();
    }

    @PUT
    @Path("users/{userId}/credentials/{credentialId}/approval")
    public Response approve(@PathParam("userId") String userId, @PathParam("credentialId") String credentialId) {
        return set(userId, credentialId, true);
    }

    @DELETE
    @Path("users/{userId}/credentials/{credentialId}/approval")
    public Response withdraw(@PathParam("userId") String userId, @PathParam("credentialId") String credentialId) {
        return set(userId, credentialId, false);
    }

    private Response set(String userId, String credentialId, boolean approve) {
        UserModel user = user(userId);
        auth.users().requireManage(user);
        CredentialModel credential = user.credentialManager().getStoredCredentialById(credentialId);
        if (credential == null || !Passkeys.TYPE.equals(credential.getType())) {
            throw new NotFoundException("No WebAuthn credential " + credentialId + " for this user");
        }
        if (approve && Passkeys.keptOffGold(session, realm, user, credentialId)) {
            // a synced key (BE=1 at registration) signs in but is never approved
            return Response.status(Response.Status.CONFLICT).type(MediaType.APPLICATION_JSON)
                    .entity(Map.of("error", "chowkidar_passkey_synced",
                            "error_description", "a synced (backup-eligible) key is never approved"))
                    .build();
        }
        Set<String> ids = user.getAttributeStream(Passkeys.USER_APPROVED)
                .collect(java.util.stream.Collectors.toCollection(LinkedHashSet::new));
        ids.retainAll(Passkeys.credentialIds(user));
        if (approve) {
            ids.add(credentialId);
        } else {
            ids.remove(credentialId);
        }
        Passkeys.setApproved(user, ids);
        adminEvent.operation(approve ? OperationType.UPDATE : OperationType.DELETE)
                .resourcePath(session.getContext().getUri())
                .success();
        return Response.noContent().build();
    }

    private UserModel user(String userId) {
        UserModel user = session.users().getUserById(realm, userId);
        if (user == null) {
            auth.users().requireQuery();
            throw new NotFoundException("No such user");
        }
        return user;
    }

    private static Map<String, Object> row(CredentialModel c, boolean approved) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("credentialId", c.getId());
        row.put("userLabel", c.getUserLabel());
        row.put("createdDate", c.getCreatedDate());
        row.put("approved", approved);
        return row;
    }
}
