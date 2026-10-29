<#-- Copyright 2026 Ploutos Services LLC · SPDX-License-Identifier: Apache-2.0 -->
<#-- Chowkidar: the door asks before switching accounts (SwitchingBrokerRedirector). -->
<#import "template.ftl" as layout>
<@layout.registrationLayout; section>
    <#if section = "header">
        Switch account?
    <#elseif section = "form">
        <p>You are signed in as <strong>${chowkidarSwitchFrom}</strong>.</p>
        <form id="chowkidar-switch" action="${url.loginAction}" method="post">
            <button class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!}"
                    name="chowkidar_switch" value="switch" type="submit">Switch to ${chowkidarSwitchTo}</button>
            <button class="${properties.kcButtonClass!} ${properties.kcButtonSecondaryClass!} ${properties.kcButtonBlockClass!}"
                    name="chowkidar_switch" value="stay" type="submit">Stay as ${chowkidarSwitchFrom}</button>
        </form>
    </#if>
</@layout.registrationLayout>
