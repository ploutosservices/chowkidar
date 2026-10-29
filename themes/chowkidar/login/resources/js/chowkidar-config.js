/*
 * Copyright 2026 Ploutos Services LLC
 * SPDX-License-Identifier: Apache-2.0
 */
/* The settings the sign-in page's title bar reads (js/chowkidar-bar-v6.js). Edit them for your deployment.
 *   cdn         where the shared title bar's stylesheet is served: the bar loads <cdn>/estate/titlebar/titlebar.css.
 *               That stylesheet is not part of this project (it belongs to the dvar shell); serve your own under that
 *               path, or leave this empty: the page then keeps Keycloak's own look under an unstyled bar.
 *   envColours  the bar's colour per environment; the environment is the realm's name ("production" shows no word). A realm with no colour
 *               wears the stylesheet's "undeclared" red, never production's.
 *   hosts       each application's host (as in its redirect_uri, port included) to its tenant. A sign-in page
 *               whose application host maps to no tenant offers no way in: it says you arrived in error.
 *   icons       each client's logo URL, by client_id; absent, Chowkidar's mark.
 *   names       each client's application name, by client_id; absent, the realm's display name.
 * Keycloak serves theme files with a long cache lifetime: rename this file (and theme.properties) when it changes. */
window.CHOWKIDAR_ESTATE = {
  "cdn": "",
  "envColours": {"demo": "#134e4a"},
  "hosts": {"house-python.localhost:8443": "acme", "house-node.localhost:8443": "acme"},
  "icons": {},
  "names": {"house-python": "Python house", "house-node": "Node house"}
};
