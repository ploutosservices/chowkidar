/*
 * Copyright 2026 Ploutos Services LLC
 * SPDX-License-Identifier: Apache-2.0
 */
/* Chowkidar's title bar: the sign-in page looks like the applications behind it, with tenant,
 * environment, logo and colors.
 *
 * The bar is the shared title bar: its stylesheet is on the CDN
 * (<cdn>/estate/titlebar/titlebar.css) and its fixed skeleton. Nothing here restyles it.
 *   environment — the realm in the path (/realms/<realm>/…); its colour from window.CHOWKIDAR_ESTATE
 *                 (the realm's configured environment colours). No colour means the stylesheet's undeclared red, never production's.
 *                 production shows no word, as everywhere.
 *   tenant      — the host of the application's return address (redirect_uri on the first page; kept in
 *                 sessionStorage for the pages after it, which no longer carry it), mapped to its tenant
 *                 by the deployment's tenant map. The application's OWN name and logo for that tenant, when it
 *                 serves them, from <its origin>/.well-known/estate-brand.json ({"name": …, "logo": …,
 *                 "app": …}; the application publishes this file) —
 *                 the application owns its tenants' names and logos; the sign-in server holds no copy.
 *   app         — the tenant's own name for the application ("app", when the tenant has one) replaces the
 *                 manifest's name in the bar's application cell, the card header and the tab title.
 *   logo        — that logo, else Chowkidar's mark (the dark one: the logo cell is white).
 * This file holds no deployment fact: to add an environment colour or a tenant, edit chowkidar-config.js
 * (rename it and theme.properties' reference, because Keycloak caches theme files for long).
 *
 * NO TENANT, NO WAY IN: the sign-in page, unless it gets a tenant and environment, does not
 * display login options; it simply says that you have arrived here in error. The environment is
 * the realm; the tenant is the return address's host as above. A page that offers a way in (the address box,
 * a password, a provider button, a key) for no tenant shows only "You have arrived here in error", under the
 * same bar. The door's own person-facing pages are their own case, named, never an error:
 *   account-console / account  — "where am I signed in" : context "Your account"
 *   security-admin-console     — a realm's admin console: context "Administration"
 *   a loopback return address (localhost, 127.0.0.1) outside production — a developer's own app: "Local"
 * The master realm is the door's own administration and is never touched. A page with no way in (an error,
 * an expired link) is left as Keycloak drew it. Without script the page is Keycloak's own, as before.
 * Versioned in its name, because Keycloak serves theme files max-age 30 days. */
(function () {
  "use strict";
  var E = window.CHOWKIDAR_ESTATE || {};
  var m = location.pathname.match(/\/realms\/([^\/]+)\//);
  var realm = m ? decodeURIComponent(m[1]) : "";
  if (!realm || realm === "master") return;

  var client = "";
  try { client = new URLSearchParams(location.search).get("client_id") || ""; } catch (e) { client = ""; }
  /* kept per realm AND client, so one application's return address never labels another's page */
  var host = "", key = "chowkidar.return." + realm + "." + client;
  try {
    var ru = new URLSearchParams(location.search).get("redirect_uri");
    if (ru) { host = new URL(ru).host; sessionStorage.setItem(key, host); }
    else { host = sessionStorage.getItem(key) || ""; }
  } catch (e) { host = ""; }

  var tenant = (E.hosts || {})[host] || "";
  var OWN = { "account-console": "Your account", "account": "Your account", "security-admin-console": "Administration" };
  var label = tenant ? tenant.charAt(0).toUpperCase() + tenant.slice(1) : "";
  if (!label && OWN[client]) label = OWN[client];
  if (!label && realm !== "production" && /^(localhost|127\.0\.0\.1)(:\d+)?$/.test(host)) label = "Local";
  var colour = (E.envColours || {})[realm] || "";
  var cdn = (E.cdn || "").replace(/\/+$/, "");
  var mark = (function () {
    var s = document.querySelector('script[src*="chowkidar-bar-v6.js"]');
    return s ? s.src.replace(/js\/chowkidar-bar-v6\.js.*$/, "img/chowkidar-dark-v1.svg") : "";
  })();
  /* THE PAGE NAMES THE APPLICATION (when the application is known, its name replaces the door realm's name):
     the name the client's application declares in its manifest (E.names, by client_id) replaces the
     realm's name in the card header and the tab title. No name declared, or no client → the realm's, as before.
     The bar's application cell follows the same rule (Chowkidar is the default name of the app; if the app name is known, it is shown). */
  var appName = (E.names || {})[client] || "";
  /* THE DEFAULT LOGO IS THE APPLICATION'S ICON (with nothing known it shows the
     default, and the default logo is the app icon): the icon the client's application declares in its manifest
     (E.icons, by client_id). Chowkidar's mark only where no application declares one — the door's own pages. */
  var appIcon = (E.icons || {})[client] || "";
  var dflt = appIcon || mark;

  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text) n.textContent = text;
    return n;
  }

  function draw() {
    if (cdn && !document.querySelector('link[data-chowkidar-bar]')) {
      var l = document.createElement("link");
      l.rel = "stylesheet"; l.href = cdn + "/estate/titlebar/titlebar.css"; l.setAttribute("data-chowkidar-bar", "");
      document.head.appendChild(l);
    }
    var bar = el("header", "estate-bar chowkidar-bar");
    bar.setAttribute("data-env", realm);
    if (colour) bar.style.setProperty("--estate-env-color", colour);

    var logo = el("span", "estate-bar-logo");
    var img = document.createElement("img");
    img.src = dflt; img.alt = appIcon ? client : "Chowkidar";
    logo.appendChild(img);

    var main = el("div", "estate-bar-main");
    var appCell = el("span", "estate-bar-app", appName || "Chowkidar");
    main.appendChild(appCell);
    var ctx = el("span", "estate-bar-context", label);
    if (!label) ctx.hidden = true;
    main.appendChild(ctx);
    if (realm !== "production") main.appendChild(el("span", "estate-bar-env", realm.toUpperCase()));
    main.appendChild(el("div", "estate-bar-spacer"));

    bar.appendChild(logo); bar.appendChild(main);
    document.body.insertBefore(bar, document.body.firstChild);
    document.documentElement.classList.add("chowkidar-has-bar");

    var offers = document.querySelector('#kc-form-login, #kc-social-providers, #kc-select-try-another-way-form, ' +
      'input[name="username"], input[name="password"], #authenticateWebAuthnButton, #kc-form-webauthn');
    if (!label && offers) {
      var main = document.querySelector("main.pf-v5-c-login__main") || document.querySelector("#kc-content") || document.body;
      Array.prototype.forEach.call(main.children, function (c) { c.hidden = true; c.style.display = "none"; });
      var note = el("div", "pf-v5-c-login__main-body chowkidar-error");
      note.appendChild(el("h1", "pf-v5-c-title pf-m-3xl", "You have arrived here in error"));
      main.appendChild(note);
      document.documentElement.classList.add("chowkidar-no-tenant");
      return;
    }

    /* The card wears the sign-in page style this theme copies (when the tenant is known, its logo replaces
       Chowkidar's own): the tenant's logo, else the
       default above (the application's icon, else Chowkidar's mark), above the tenant's name. */
    var head = document.getElementById("kc-header-wrapper");
    var card = null;
    /* the name the title and the header show now — the realm's, or the manifest's once replaced — so a
       later, better name replaces exactly it */
    var shownName = head ? (head.textContent || "").trim() : "";
    if (head && appName) {
      /* the title is Keycloak's own message around the realm's name ("Sign in to Chowkidar"): only the name is
         replaced, never the words around it */
      if (shownName) document.title = document.title.replace(shownName, appName);
      head.textContent = appName;
      shownName = appName;
    }
    if (head) {
      card = document.createElement("img");
      card.className = "chowkidar-card-logo";
      card.src = dflt; card.alt = appIcon ? client : "Chowkidar";
      head.parentNode.insertBefore(card, head);
    }

    if (!host || !tenant) return;   /* only a tenant's application has a brand to fetch */
    var origin = "https://" + host;
    fetch(origin + "/.well-known/estate-brand.json", { mode: "cors", credentials: "omit" })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (b) {
        if (!b) return;
        /* the tenant's name fills the bar's context cell only; the header is the application's */
        if (typeof b.name === "string" && b.name) { ctx.textContent = b.name; ctx.hidden = false; }
        /* the tenant's own name for the APPLICATION:
           it is the application's name, so it takes the application's three places — never b.name, the
           tenant's, which stays out of the header */
        if (typeof b.app === "string" && b.app.trim()) {
          var app = b.app.trim();
          appCell.textContent = app;
          if (head) {
            if (shownName) document.title = document.title.replace(shownName, app);
            head.textContent = app;
            shownName = app;
          }
        }
        if (typeof b.logo === "string" && b.logo) {
          var src = new URL(b.logo, origin + "/").href;
          img.src = src; img.alt = b.name || img.alt;
          if (card) { card.src = src; card.alt = b.name || card.alt; card.classList.add("chowkidar-card-logo-tenant"); }
        }
      })
      .catch(function () { /* the application serves no brand yet: the tenant's key and Chowkidar's mark stay */ });
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", draw);
  else draw();
})();
