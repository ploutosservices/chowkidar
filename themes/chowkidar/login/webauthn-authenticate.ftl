<#-- Copyright 2026 Ploutos Services LLC · SPDX-License-Identifier: Apache-2.0 -->
<#-- Chowkidar's copy of Keycloak 26.4.4's keycloak.v2 webauthn-authenticate.ftl, changed in three
     places. (0) In a realm named "admin" the header says "Confirm it's you" and a "Not now" button is added, because
     the page there is a step onto a live session, not a login. (1) The list of registered keys is not drawn: large
     display-only boxes that do nothing; the hidden authn_select form stays. (2) When the address router serves this
     page as the key as a way in (chowkidarKeyWayIn), it carries "not this way": forget the person, show every way in.
     The step-up serves the same page without it. Re-copy from the new parent on a Keycloak upgrade. -->
<#import "template.ftl" as layout>
<#import "buttons.ftl" as buttons>
<@layout.registrationLayout displayInfo=(realm.registrationAllowed && !registrationDisabled??); section>
<!-- template: webauthn-authenticate.ftl -->

    <#if section = "title">
     title
    <#elseif section = "header">
        <#if realm.name == "admin">Confirm it's you<#else>${kcSanitize(msg("webauthn-login-title"))?no_esc}</#if>
    <#elseif section = "form">
        <div id="kc-form-webauthn" class="${properties.kcFormClass!}" >
            <form id="webauth" action="${url.loginAction}" method="post" hidden="hidden">
                <input type="hidden" id="clientDataJSON" name="clientDataJSON"/>
                <input type="hidden" id="authenticatorData" name="authenticatorData"/>
                <input type="hidden" id="signature" name="signature"/>
                <input type="hidden" id="credentialId" name="credentialId"/>
                <input type="hidden" id="userHandle" name="userHandle"/>
                <input type="hidden" id="error" name="error"/>
            </form>

                <#if authenticators??>
                    <form id="authn_select" class="${properties.kcFormClass!}" hidden="hidden">
                        <#list authenticators.authenticators as authenticator>
                            <input type="hidden" name="authn_use_chk" value="${authenticator.credentialId}"/>
                        </#list>
                    </form>

                </#if>

            <@buttons.actionGroup>
                <@buttons.button id="authenticateWebAuthnButton" label="webauthn-doAuthenticate" class=["kcButtonPrimaryClass","kcButtonBlockClass"]/>
            </@buttons.actionGroup>
            <#if realm.name == "admin">
                <#-- "Not now": back to the application without the key (for a person who does not want to be on
                     the admin page). The page's own form posts error=not_now; the authenticator sends the browser back
                     with access_denied. -->
                <button class="${properties.kcButtonClass!} ${properties.kcButtonSecondaryClass!} ${properties.kcButtonBlockClass!}" type="button"
                        onclick="document.getElementById('error').value='not_now'; document.getElementById('webauth').requestSubmit ? document.getElementById('webauth').requestSubmit() : document.getElementById('webauth').submit();">Not now</button>
            </#if>
            <#if chowkidarKeyWayIn??>
                <form id="chowkidar-not-this-way" action="${url.loginAction}" method="post">
                    <input type="hidden" name="chowkidar_not_this_way" value="1"/>
                    <button class="${properties.kcButtonClass!} ${properties.kcButtonSecondaryClass!} ${properties.kcButtonBlockClass!}" type="submit">${msg("chowkidarNotThisWay")}</button>
                </form>
            </#if>
        </div>
    <script type="module">
        import { authenticateByWebAuthn } from "${url.resourcesPath}/js/webauthnAuthenticate.js";
        const authButton = document.getElementById('authenticateWebAuthnButton');
        authButton.addEventListener("click", function() {
            const input = {
                isUserIdentified : ${isUserIdentified},
                challenge : '${challenge}',
                userVerification : '${userVerification}',
                rpId : '${rpId}',
                createTimeout : ${createTimeout?c},
                errmsg : "${msg("webauthn-unsupported-browser-text")?no_esc}"
            };
            authenticateByWebAuthn(input);
        }, { once: true });
    </script>

    <#elseif section = "info">
        <#if realm.registrationAllowed && !registrationDisabled??>
            <div id="kc-registration">
                <span>${msg("noAccount")} <a href="${url.registrationUrl}">${msg("doRegister")}</a></span>
            </div>
        </#if>
    </#if>
</@layout.registrationLayout>
