<#-- Copyright 2026 Ploutos Services LLC · SPDX-License-Identifier: Apache-2.0 -->
<#-- Chowkidar: the one signed-out page. Keycloak 26.4.4's base login-x509-info.ftl, the
     certificate step's confirmation page, shown to a certificate holder with no door session: right after any app's
     sign-out, or on a first visit. It says so and offers the realm's ways in as buttons (Google, Microsoft); the
     certificate's own submit is shown only when the realm has no broker (no input, the buttons). -->
<#import "template.ftl" as layout>
<#import "social-providers.ftl" as identityProviders>
<@layout.registrationLayout displayInfo=false; section>
    <#if section = "header">
        You are signed out
    <#elseif section = "form">
        <#if !(social?? && social.providers?? && social.providers?has_content)>
        <form id="kc-x509-login-info" class="${properties.kcFormClass!}" action="${url.loginAction}" method="post">
            <div id="kc-form-buttons" class="${properties.kcFormButtonsClass!}">
                <input class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!} ${properties.kcButtonLargeClass!}"
                       name="login" id="kc-login" type="submit" value="Sign in"/>
            </div>
        </form>
        </#if>
    <#elseif section = "socialProviders">
        <#if social?? && social.providers?? && social.providers?has_content>
            <@identityProviders.show social=social/>
        </#if>
    </#if>
</@layout.registrationLayout>
