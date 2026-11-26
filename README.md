# MFA for GLPI

An OTP plugin for GLPI

[![License](https://img.shields.io/badge/License-GNU%20AGPLv3-blue.svg)](https://github.com/ticgal/borgbase/blob/master/LICENSE)
[![Twitter](https://img.shields.io/badge/Twitter-TICGAL-blue.svg)](https://twitter.com/ticgalcom)
[![TICGAL](https://img.shields.io/badge/Web-TICGAL-blue.svg)](https://tic.gal/)
[![Localazy](https://img.shields.io/badge/Translate-Localazy-cyan)](https://localazy.com/p/mfauth#translations)


# How to use it

Please check the info here: https://tic.gal/en/mfa-for-glpi-does-exactly-what-you-think/

# Requirements and recovery

The security code is sent by e-mail, so GLPI e-mail notifications must be enabled, the notification
"One-Time Security Code generated" must be active, and every user covered by MFA needs an e-mail address.
The configuration tab warns when notifications are disabled. If nobody can sign in because codes cannot be
delivered, deactivate the plugin from the console and fix the setup:

    php bin/console plugin:deactivate mfa

If the plugin folder was deleted without uninstalling it, its tables (`glpi_plugin_mfa_configs`,
`glpi_plugin_mfa_mfas`) stay in the database with their configuration, and that configuration applies again as soon
as the plugin is reinstalled. If e-mail cannot be delivered, either fix the notifications or clean it up first:
uninstall the plugin properly, drop the two tables, or set the authentication types to "No":

    UPDATE glpi_plugin_mfa_configs SET local = 0, mail = 0, ldap = 0, external = 0;

The configuration tab refuses to turn an authentication type on while codes cannot be delivered, and activating the
plugin warns when a stored configuration would lock users out.

## What the plugin covers

The code is enforced on every web request, whatever opened the session (login form, "remember me" cookie...).
While a code is pending the session carries no user at all: its identity is kept aside by the plugin and put
back once the code is verified, so the legacy REST API (`Session-Token`), the high-level API authorisation
endpoint or any other code that trusts the session find nobody logged in.

| Entry point | Behaviour |
|---|---|
| Web login (form, "remember me" cookie) | Code required |
| Legacy REST API `initSession` with login and password | Refused when the account needs a code |
| CalDAV (password only) | Refused when the account needs a code |
| High-level API OAuth `password` grant | Refused when the account needs a code |
| Impersonation | Allowed from a verified session, no new code |
| Legacy REST API `initSession` with `user_token`, OAuth tokens already issued, command line | Not covered: a token is a different credential, not the password |

Users with GLPI native 2FA are not asked twice, but only when their TOTP existed before the login started. A TOTP
enrolled during the login (core "/MFA/Setup" step) does not count, because whoever typed the password created it.
A user who skips a native 2FA setup during a grace period has verified no second factor and is asked for the code.

Limitations:
- The guard runs in the `post_init` hook. While GLPI suspends plugin execution (after a core update until an
  administrator resumes it, or manually) no guard runs and logins complete without the code.
- The account type decides who needs a code: local, mail, LDAP, external (SSO) and CAS/x509 each have their own
  switch. Any other type is never asked for a code.
- A TOTP enrolled by whoever typed the password in the native 2FA setup step stays on the account (core behaviour).
  The plugin no longer treats it as a second factor, but an administrator has to reset it.
- Limits are per user: someone who knows a password can lock the real user out for 15 minutes.
- The code is always asked for on a new session, including when it is restored from a "remember me" cookie.

# Contribute

Please, fell free to suggest an enhancement of fix via a PR.

# Translations
Translations are handled at Localazy. 

Please head there and add your language: https://localazy.com/p/mfauth

As for GLPI, all translations must use the country code to be accepted.
- fr (Not valid)
- fr_CA (Valid)

All translation contributions are under the [Creative Commons Attribution 4.0 International License](https://spdx.org/licenses/CC-BY-4.0.html)
