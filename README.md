# chowkidar

*Chowkidar* (चौकीदार) is the watchman at a gate. This is a guard for a
[Keycloak](https://www.keycloak.org/) sign-in server: a set of Keycloak extensions, a login and account
theme, and a sample realm you can import. Every part is open source (Apache-2.0).

It is the gate of *dvar*, the front-door project in which several independent applications share one sign-in.
You can use Chowkidar on its own. The tested version is **Keycloak 26.4.4**; the pom, the Dockerfile and the
templates all name it, and nothing else has been tried.

## Words used here

| Word | Meaning |
|---|---|
| door | the Keycloak sign-in server, as the people and applications see it |
| house | an application that signs its people in through the door (an OpenID Connect client) |
| tenant | the customer or organisation a house is run for; the theme maps a house's host to one |
| level, silver, gold | how strongly a session is proven. Silver is level 1 (acr `1`), gold is level 2 (acr `2`). A house asks for one with `acr_values` |
| the bar | the title bar the sign-in page draws across the top, showing application, tenant and environment |
| act as | an administrator signing in to a house as another person, through the admin console's impersonation |
| device-bound passkey | a WebAuthn credential that lives on one device (backup-eligible flag `BE=0`) |
| synced passkey | a WebAuthn credential the platform backs up and shares across devices (`BE=1`) |
| dvar | the front-door project this is the gate of |

## What is in it

| Path | What it is |
|---|---|
| `passkey-extension/` | Keycloak providers, Java, built with Maven (`pom.xml`) |
| `themes/chowkidar/login` | the sign-in pages: a child of Keycloak's `keycloak.v2` theme, with a title bar |
| `themes/chowkidar/account` | the account console: a child of Keycloak's `keycloak.v3` account theme, with the mark |
| `realm/demo-realm.json` | the realm `demo`: a bare shell with two placeholder clients (see "Try it") |
| `Dockerfile`, `docker-compose.yml` | Keycloak with the extension and theme built in, and the realm imported |

Theme files carry a version in their names (`chowkidar-v4.css`, `chowkidar-bar-v6.js`). Keycloak serves theme
files with a long cache lifetime under a path that does not change, so a changed file gets a new name and
`theme.properties` is updated to match. Do the same when you edit one.

## The providers

Each is a standard Keycloak SPI implementation. You add it to a flow or turn it on in a realm, and it does
nothing until you do. The ids are what the admin console lists and what the realm JSON names.

### Authenticators and conditions

- **Passkey (approved)** (`chowkidar-passkey-authenticator`): Keycloak's WebAuthn second factor, with
  three differences. A credential counts only when an administrator has approved it. The credential that
  verified the session is recorded on it (user-session note `chowkidar.passkey.verifiedBy`), so deleting
  that credential can end exactly the sessions it verified. A person who cannot satisfy it is sent back to
  the house with `access_denied` instead of being left on a sign-in page the house never hears from (see
  "Error codes"). Setup during sign-in is not offered: a person enrols a key in the account console, and it
  waits for approval. When the realm sets `chowkidar.passkey.refuseBackupEligible`, a key recorded as
  synced is refused here even if approved.
- **Passkey registration** (`webauthn-register`, replacing Keycloak's own under the same id): Keycloak's
  registration, plus one record. A credential whose authenticator data carries the backup-eligible flag is
  added to the user attribute `chowkidar.passkey.backupEligible`. The flag is read from the authenticator
  data; attestation is not requested. It records the flag in every realm and registers synced keys like any
  other.
- **Email first (last way in)** (`chowkidar-address-router`): see "Email first" below.
- **Certificate step-up (keeps the user)** (`chowkidar-certificate-step-up`): raises the level of the
  session the person already has when the request carries a valid, trusted client certificate that is one of
  that user's machines. It never changes the user and never links accounts. See "Certificate step-up".
- **Condition - level requested** (`chowkidar-requested-level`): matches when the house asked, with
  `acr_values`, for at least the configured level. Keycloak's own *Condition - Level of Authentication* asks
  whether a level is still to be reached, which in a broker's post-login flow is always yes; this one asks
  whether the level was asked for.
- **Condition - upstream vouched for the email** (`chowkidar-broker-email-vouched`): in a first broker
  login, matches when the brokered identity carries the configured attribute with the value `true` or `1`
  (default attribute `xms_edov`, Microsoft Entra's "email domain owner verified", copied there by the
  broker's attribute mapper). With *Negate* it matches the other case, so one flow can hold a link-by-email
  branch and a confirm-and-verify branch.
- **Identity Provider Redirector (switching)** (`chowkidar-switching-redirector`): follows the house's
  `kc_idp_hint`. When the person already signed in at the door is not linked to the hinted provider, it
  asks "Switch to X / Stay as Y"; Switch ends that session and restarts the same authorization request,
  Stay returns to the house as the person already is. A person linked to the hinted provider keeps the
  session.

### Event listeners and the admin API

- **Passkey revoked** (`chowkidar-passkey`): when a WebAuthn credential is deleted (by the user or an
  administrator), every session it verified ends by back-channel logout and its approval is withdrawn.
- **Last way in** (`chowkidar-last-way-in`): on each `LOGIN` event, records the broker alias, or
  `certificate`, in the user attribute `chowkidarLastWayIn`. A sign-in answered by the session alone records
  nothing.
- **Disable signs out** (`chowkidar-disable-signout`): when an administrator disables a user, every session
  of that user ends by back-channel logout. Keycloak 26.4.4 alone sends none, so houses keep their sessions.
- **Passkey approval** (`chowkidar-passkeys`), under the admin API of a realm:

      GET    /admin/realms/{realm}/chowkidar-passkeys/pending
      GET    /admin/realms/{realm}/chowkidar-passkeys/users/{userId}
      PUT    /admin/realms/{realm}/chowkidar-passkeys/users/{userId}/credentials/{credentialId}/approval
      DELETE /admin/realms/{realm}/chowkidar-passkeys/users/{userId}/credentials/{credentialId}/approval

  Reading needs `view-users`; approving needs `manage-users` on that user. There is no screen for it in
  the admin console. Approving a key recorded as synced, in a realm that refuses them, answers `409` with
  `chowkidar_passkey_synced`.

**The three listener ids `chowkidar-passkey`, `chowkidar-last-way-in` and `chowkidar-disable-signout` do
nothing until you add them to the realm's *Event listeners*** (Realm settings, Events). `chowkidar-disable-signout`
reads administrator events, so the realm's admin events must be enabled; the other two read user events
(`LOGIN`, `REMOVE_CREDENTIAL`) and the admin events for credential deletion. The demo realm has both on.

### Email first

`chowkidar-address-router` has three behaviours, all at the lower level (silver):

1. **Passkey button.** "Sign in with a passkey" runs Keycloak's passwordless WebAuthn with no person named
   first: the browser lists every passkey held for this door and the one chosen names the user. The people
   need a passwordless WebAuthn credential (Keycloak's "WebAuthn Register Passwordless"). The approval
   described above is not consulted on this path.
2. **Key sign-in from a typed address.** Only where the realm attribute `chowkidar.passkey.signIn` is
   `true`. An enabled person who holds an enrolled (second-factor) key is asked for that key. Any enrolled
   key signs in at silver. A key that is approved, and not kept off gold by `refuseBackupEligible`, signs in
   at gold. If the house asked for gold and the key is not such a key, the person goes back to the house with
   `access_denied` / `chowkidar_passkey_not_approved` before the signature is checked. The page carries "Not
   this way", which forgets the person and shows every way in. Any other address goes to the person's last
   way in (a broker, or the certificate, which hands over to the next step of the flow). For an unknown address,
   or a person with several brokers and no recorded way, it shows every way in.
3. **Lost your way in?** Asks the address plus a code from the authenticator app (TOTP) the person set up
   earlier. A match signs in at silver, never gold: a house that asked for gold gets `access_denied` for every
   address. Every failure shows the same page and the same message ("That code did not match."). Five wrong
   codes in fifteen minutes stop the check for that user; the count is the user attribute
   `chowkidarRecoveryFailures`. The successful `LOGIN` event carries the detail `chowkidar_recovered=1`.

The typed address only routes: whoever the broker, the certificate or the key names is who signs in.

The shipped `login-username.ftl` draws no address box on the first page: it draws the realm's provider
buttons, "Sign in with a passkey" and "Lost your way in?", and the address box only on the recovery page.
Behaviour 2 therefore runs only if you give the page an address field of your own.

### Certificate step-up

The step reads the client certificate from the request, so it needs all of these:

- a **reverse proxy** that terminates TLS, asks the browser for a client certificate and forwards it, and
  Keycloak's **x509 lookup SPI** (`X509ClientCertificateLookup`) configured for that proxy
  (see Keycloak's reverse-proxy guide on X.509 client certificate lookup; it has nginx, haproxy and apache variants);
- a **truststore** in Keycloak holding the CA that issued the certificates (`truststore-paths`);
- the user attribute **`chowkidarMachines`**, one value per machine: the certificate's CN must equal one of
  them, so a certificate belongs to a user's machine, never to a login;
- the authenticator config **`subject_regex`**, a Java regular expression searched in the certificate's
  subject DN (RFC 2253 form, for example `CN=ada-laptop,O=Acme`). With none configured every certificate is
  refused.

The CN convention in your own deployment is yours (`<person>-<machine>@<environment>` is one example, not a
requirement). The step also requires the certificate to be valid now and issued directly by a CA in the
truststore. On success it records the subject on the session (note `certificate_subject`) so a token mapper
can carry it.

## Wiring the providers

The extension adds steps; **you** arrange the flow. This worked example gives a realm email-first sign-in
and asks for a second proof when a house asks for gold. Create it in Authentication, Flows, and bind it as
the browser flow. `Alternative`, `Required` and `Conditional` are the requirement settings.

    chowkidar browser                                  (top-level flow)
      Identity Provider Redirector (switching)         Alternative   (the house's kc_idp_hint)
      Cookie                                           Alternative
      Email first (last way in)                        Alternative
      X509/Validate Username Form                      Alternative   (only if certificates are a way in)

Email first is an Alternative beside the certificate step on purpose: for a person whose last way in is
the certificate it steps aside and the flow continues to the next Alternative; for a broker it redirects.

A broker's return ends the browser flow before any later level, so the step to gold goes in a **post-login
flow** bound to every identity provider (Identity providers, the provider, *Post login flow*):

    chowkidar after broker                             (top-level flow)
      chowkidar level 2                                Conditional   (sub-flow)
        Condition - level requested                    Required      level = 2
        Condition - Level of Authentication            Required      `loa-condition-level` 2, `loa-max-age` 3600
        Passkey (approved)                             Required
      Allow access                                     Required

Replace *Passkey (approved)* with *Certificate step-up* (config `subject_regex`) to ask for the certificate
instead; keep both, each `Required`, to ask for both. *Certificate step-up* offers only `Required` and `Disabled`. The
*Condition - level requested* step is needed after a broker because Keycloak's own level condition always
matches there. In the browser flow, where it does not, Keycloak's documented step-up shape works: a
`Conditional` sub-flow per level, each starting with *Condition - Level of Authentication*.

Then, in the realm:

1. Realm settings, General: set the ACR to LoA mapping `silver` = `1`, `gold` = `2`. The extension compares
   the numbers 1 and 2; the names are only what houses write in `acr_values`.
2. Realm settings, Events: add the listener ids above; keep Save events and admin events on.
3. Realm settings, User profile: leave *Unmanaged attributes* off, or administrator-only (see "Security
   notes").
4. Optionally set `chowkidar.passkey.signIn` and `chowkidar.passkey.refuseBackupEligible` (see below).

## Configuration reference

**Realm attributes** (Realm settings, or the realm JSON `attributes`):

| Key | Default | Effect |
|---|---|---|
| `chowkidar.passkey.refuseBackupEligible` | `false` | `true` keeps keys recorded as synced away from gold: *Passkey (approved)* refuses them, key sign-in reaches only silver with them, and approving one answers 409 |
| `chowkidar.passkey.signIn` | `false` | `true` lets a person who holds an enrolled key sign in with it from the address page (behaviour 2) |
| `acr.loa.map` | none (Keycloak's) | maps the names houses ask for to numbers; the extension itself uses 1 (silver) and 2 (gold), fixed in the code |

**User attributes** (the user's *Attributes* tab, or the admin API):

| Key | Set by | Effect |
|---|---|---|
| `chowkidar.passkey.approved` | the approval API | ids of the user's WebAuthn credentials an administrator approved |
| `chowkidar.passkey.backupEligible` | passkey registration | ids of credentials registered with `BE=1`. A credential not in it counts as device-bound |
| `chowkidarMachines` | you | the CNs of the user's machines, for the certificate step-up |
| `chowkidarLastWayIn` | the listener, the router | `certificate`, `passkey`, or a broker alias; where email first sends the person next |
| `chowkidarRecoveryFailures` | the router | millisecond timestamps of recent wrong recovery codes (the throttle) |

**Authenticator configuration** (the gear on the execution):

| Provider | Key | Default | Effect |
|---|---|---|---|
| Certificate step-up | `subject_regex` | none: all refused | regular expression searched in the certificate's subject DN |
| Condition - level requested | `level` | none: never matches | the number the house must have asked for, at least |
| Condition - upstream vouched | `attribute` | `xms_edov` | brokered attribute that says the upstream vouched for the address |
| Condition - upstream vouched | `negate` | `false` | match when the upstream did not vouch |

**Request parameters** (sent by the house on its authorization request):

| Parameter | Read by | Effect |
|---|---|---|
| `acr_values` | Keycloak, then the conditions and the router | the level asked for; 2 or more means gold |
| `kc_idp_hint` | the switching redirector | the provider to go to, and the switch question |
| `chowkidar_reason` | the sign-in page | why the person is sent here. One of `signed_out`, `certificate_needed`, `session_expired`, `sign_in_again`; the page shows its own words for it and ignores any other value |
| `client_id`, `redirect_uri` | the bar | the application name, and the host that maps to a tenant |

**Session notes** written: `chowkidar.passkey.verifiedBy` (credential ids that verified the session) and
`certificate_subject`.

## Error codes the house receives

A step that cannot be satisfied sends the browser back to the house's redirect address with
`error=access_denied` and one `error_description`:

| `error_description` | Meaning |
|---|---|
| `chowkidar_passkey_required` | the person holds no key |
| `chowkidar_passkey_not_approved` | the keys held are not approved (or are kept off gold), or the key used is not; also: a gold request through key sign-in with a key that cannot reach it, or through recovery |
| `chowkidar_passkey_not_given` | the key page was answered with an error or cancelled ("Not now" in a realm named `admin`) |
| `chowkidar_passkey_failed` | the key did not verify |
| `chowkidar_certificate_required` | no certificate came with the request |
| `chowkidar_certificate_refused` | the certificate is not valid now, does not match `subject_regex`, is not issued by a trusted CA, or is not one of the user's machines |

## Try it

You need Docker with Compose. The compose file is a development server (`start-dev`, a store inside the
container), not a production setup.

    cp .env.example .env      # replace every CHANGEME in it
    docker compose up --build

Then open `http://localhost:8080/admin/` (the admin from `.env`) and
`http://localhost:8080/realms/demo/.well-known/openid-configuration`.

**The `demo` realm is a bare shell.** Its browser flow is Keycloak's stock one, no Chowkidar authenticator is
in any flow, its only event listener is `jboss-logging`, and it has no users and no identity providers.
The login theme hides the stock username and password form, so its sign-in page offers no way in until you
wire a flow ("Wiring the providers") and add a user and a provider. What it does give you: a realm that boots with
the theme set, admin events on, and two clients to point a flow at.

The clients `house-python` and `house-node` are confidential OpenID Connect clients with PKCE and
back-channel logout. Their secrets come from `.env` at import: the realm file carries
`${HOUSE_PYTHON_CLIENT_SECRET}` and `${HOUSE_NODE_CLIENT_SECRET}`, never a value. Their addresses
(`https://house-*.localhost:8443`) are placeholders for the sample houses of the dvar demo; nothing here
listens there. Change them for your own applications, and change `hosts`, `icons` and `names` in
`chowkidar-config.js` to match.

The realm file holds no signing keys: Keycloak generates fresh ones on import.

## Install into an existing Keycloak

Build the jar (below), then on a Keycloak 26.4.4 server:

    cp chowkidar-passkey.jar  <keycloak>/providers/
    cp -r themes/chowkidar    <keycloak>/themes/
    <keycloak>/bin/kc.sh build      # then start as usual

Select the themes in the realm (Realm settings, Themes: login and account `chowkidar`), import
`realm/demo-realm.json` if you want it, and wire a flow.

## Build the extension alone

    docker run --rm -v "$PWD/passkey-extension:/src" -w /src maven:3.9.9-eclipse-temurin-21 mvn -B -q package
    # -> passkey-extension/target/chowkidar-passkey.jar

The pom fixes the build timestamp, so the same source gives the same jar.

## The theme

The login theme is a child of `keycloak.v2`; only the files in this repository differ. The sign-in page
draws a title bar across the top, the bar the houses behind the door wear: application, tenant and
environment. `themes/chowkidar/login/resources/js/chowkidar-config.js` (published here from
`chowkidar-config.js`) holds its settings:

- `cdn`: where the bar's stylesheet is served (`<cdn>/estate/titlebar/titlebar.css`). **That stylesheet is
  not shipped here**; it belongs to the dvar shell. With `cdn` empty the bar is drawn unstyled over Keycloak's
  own look.
- `envColours`: a colour per environment. **The environment is the realm's name.** A realm named
  `production` shows no environment word; any other shows its name in capitals.
- `hosts`: each house's host, as in its `redirect_uri` with the port, to its tenant. **A sign-in page whose
  host maps to no tenant offers no way in** and says "You have arrived here in error". Exceptions: the
  account console, the admin console, and a loopback host (`localhost`, `127.0.0.1`) in a realm that is not
  `production`, which are named, not refused. The `master` realm is left alone.
- `icons`, `names`: a logo URL and an application name per `client_id`; absent, Chowkidar's mark and the
  realm's display name.

For a mapped tenant the bar also asks the house for `https://<house host>/.well-known/estate-brand.json`
(no credentials; the house must allow the door's origin with CORS). Any field may be left out:

    { "name": "Acme Ltd",            // the tenant's name, shown in the bar
      "app":  "Acme Books",          // the tenant's name for the application: bar, page header, tab title
      "logo": "/img/acme.svg" }      // the tenant's logo; a relative URL resolves against the house

If the file is missing the bar keeps what the configuration gave it.

The `webauthn-authenticate.ftl` template treats a realm named `admin` specially: its header reads "Confirm
it's you" and it adds a "Not now" button that sends the person back with `chowkidar_passkey_not_given`.

## Security notes

- **The proxy must strip client-supplied certificate headers.** Keycloak's x509 lookup trusts the header the
  proxy sets. A proxy that passes through a header from the browser lets anyone claim any certificate.
- **No revocation check, and a one-level trust.** The step does not consult a CRL or OCSP, and a certificate
  is trusted only when its direct issuer is a CA in the truststore; an intermediate chain is not walked.
  Keep certificates short-lived, or remove the user's `chowkidarMachines` value to withdraw one.
- **The "Act as another user" button** on the sign-in page appears for any certificate that is valid in time;
  its issuer is not checked there. The admin console's own permissions decide what act-as can do.
- **Approvals depend on the user-profile policy.** If the realm's *Unmanaged attributes* policy is
  *Enabled*, users can edit attributes the user profile does not declare, including
  `chowkidar.passkey.approved`. The code then fails closed: `approved` reads as empty, so *Passkey
  (approved)* sends every person back with `chowkidar_passkey_not_approved` and key sign-in reaches only
  silver; and `backupEligible` reads as every credential the user has, so with `refuseBackupEligible` set
  no key reaches gold. Approving still writes the attribute and has no effect until the policy is
  *Disabled*, *Admin can view* or *Admin can edit*. Do not declare these attributes in the user profile with
  user-edit permission: the code checks the policy, not the declaration.
- **Recovery is a way in at silver with an address and an authenticator code.** Its failure throttle is
  per user, so anyone who knows an address can submit five wrong codes and stop that user's recovery for
  fifteen minutes. A house that needs gold is not affected: recovery never reaches it.
- **Key sign-in from a typed address reveals whether an address has a key**, because a person with an
  enrolled key is shown the key page and any other address is not. Recovery does not: it answers every
  failure alike.

## Known limitations

- The realm names `production`, `admin` and `master`, and the `estate-` prefix of the bar's class names and
  of `estate-brand.json` (and `CHOWKIDAR_ESTATE` in the config), are fixed in the code, not settings.
- The silver and gold numbers 1 and 2 are fixed in the code.
- English only: the templates carry English text and the theme ships `messages_en` alone.
- The tested version is Keycloak 26.4.4. The overridden templates must be re-copied from the parent theme
  on a Keycloak upgrade.
- There is no admin-console screen for approving passkeys; use the API above.

## Licence

Apache-2.0. See `LICENSE` and `NOTICE`.
