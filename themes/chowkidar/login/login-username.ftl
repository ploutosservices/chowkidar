<#-- Copyright 2026 Ploutos Services LLC · SPDX-License-Identifier: Apache-2.0 -->
<#-- Chowkidar (email first): Keycloak 26.4.4's keycloak.v2 login-username.ftl, changed (see the "no text box" note in the form: the first page is buttons only) —
     the ways in (the realm's brokers and the certificate) are drawn only when the address router asks for
     them (chowkidarChoose: an address the door does not know), never on the first page, which asks for the
     address only. AND the recovery way in: a "Lost your way in?"
     button in the form; when the router sets chowkidarLost, the page asks the address plus an authenticator code, with
     "Back", and draws no broker and no certificate. Re-copy from the new parent on a Keycloak upgrade, then re-apply both. -->
<#import "template.ftl" as layout>
<#import "field.ftl" as field>
<#import "buttons.ftl" as buttons>
<#import "social-providers.ftl" as identityProviders>
<#import "passkeys.ftl" as passkeys>
<@layout.registrationLayout displayMessage=!messagesPerField.existsError('username') displayInfo=(realm.password && realm.registrationAllowed && !registrationDisabled??); section>
<!-- template: login-username.ftl -->

    <#if section = "header">
        ${msg("loginAccountTitle")}
    <#elseif section = "form">
        <#-- WHY YOU ARE HERE: the door's own words for the application's reason code (AddressRouter REASONS). -->
        <#if chowkidarReason??>
            <div id="chowkidar-reason" class="${properties.kcAlertClass!} pf-m-info" role="status" style="margin-bottom:1rem">
                <span class="${properties.kcAlertTitleClass!}">
                <#switch chowkidarReason>
                    <#case "signed_out">You are signed out. Sign in again below.<#break>
                    <#case "certificate_needed">This page needs your certificate, and none was found.<#break>
                    <#case "session_expired">Your sign-in has expired. Please sign in again.<#break>
                    <#case "sign_in_again">Please sign in again.<#break>
                </#switch>
                </span>
            </div>
        </#if>
        <div id="kc-form">
            <div id="kc-form-wrapper">
                <#-- No text box: the page is the buttons
                     only; the address form is drawn only for the recovery way in (chowkidarLost). -->
                <#if realm.password && chowkidarLost??>
                    <form id="kc-form-login" class="${properties.kcFormClass!}" onsubmit="login.disabled = true; return true;" action="${url.loginAction}"
                          method="post">
                        <#if !usernameHidden??>
                            <div class="${properties.kcFormGroupClass!}">
                                <#assign label>
                                    <#if !realm.loginWithEmailAllowed>${msg("username")}<#elseif !realm.registrationEmailAsUsername>${msg("usernameOrEmail")}<#else>${msg("email")}</#if>
                                </#assign>
                                <@field.input name="username" label=label value=login.username!'' autofocus=true autocomplete="${(enableWebAuthnConditionalUI?has_content)?then('username webauthn', 'username')}" />
                            </div>
                        </#if>

                        <div class="${properties.kcFormGroupClass!}">
                            <#if realm.rememberMe && !usernameHidden??>
                                <@field.checkbox name="rememberMe" label=msg("rememberMe") value=login.rememberMe?? />
                            </#if>
                        </div>

                        <#if chowkidarLost??>
                            <input type="hidden" name="chowkidar_lost" value="1"/>
                            <div class="${properties.kcFormGroupClass!}">
                                <@field.input name="otp" label=msg("chowkidarRecoveryCode") value='' autocomplete="one-time-code" />
                            </div>
                        </#if>

                        <@buttons.loginButton />
                        <#if !chowkidarLost??>
                            <button class="${properties.kcButtonClass!} ${properties.kcButtonLinkClass!} chowkidar-lost" type="submit" name="chowkidar_lost" value="1">${msg("chowkidarLostWay")}</button>
                        </#if>
                    </form>
                    <#if chowkidarLost??>
                        <form id="chowkidar-recovery-back" action="${url.loginAction}" method="post">
                            <button class="${properties.kcButtonClass!} ${properties.kcButtonLinkClass!}" type="submit" name="chowkidar_not_this_way" value="1">${msg("chowkidarRecoveryBack")}</button>
                        </form>
                    </#if>
                </#if>
            </div>
        </div>
        <@passkeys.conditionalUIData />

    <#elseif section = "info" >
        <#if realm.password && realm.registrationAllowed && !registrationDisabled??>
            <div id="kc-registration">
                <span>${msg("noAccount")} <a href="${url.registrationUrl}">${msg("doRegister")}</a></span>
            </div>
        </#if>
    <#elseif section = "socialProviders" >
        <#-- Google and Microsoft are the first option on the first page, as on the sign-in page this theme copies:
             first option, in one row, smaller buttons. -->
        <#if !chowkidarLost?? && social.providers?? && social.providers?has_content>
            <@identityProviders.show social=social />
        </#if>
        <#if chowkidarConsole?? && !chowkidarLost??>
            <#-- ACT AS: shown only when the browser presented a valid certificate. Straight to the
                 console (the standard way): it asks for the person's own sign-in at gold, so the
                 person in the console is the person apps see, and no sign-out comes first. -->
            <a id="chowkidar-act-as" class="${properties.kcButtonClass!} ${properties.kcButtonSecondaryClass!} ${properties.kcButtonBlockClass!}" href="${chowkidarConsole}#/${realm.name}/users">Act as another user</a>
        </#if>
        <#-- No certificate button: the certificate is a machine, never a way in. A PASSKEY is a way in,
             optional: the browser lists every passkey held for this door. -->
        <#if !chowkidarLost??>
            <form id="chowkidar-passkey" action="${url.loginAction}" method="post">
                <button class="${properties.kcButtonClass!} ${properties.kcButtonSecondaryClass!} ${properties.kcButtonBlockClass!}" type="submit" name="chowkidar_passkey" value="1">Sign in with a passkey</button>
            </form>
        </#if>
    </#if>

</@layout.registrationLayout>
