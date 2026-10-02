# MFA for GLPI

An OTP plugin for GLPI

[![License](https://img.shields.io/badge/License-GNU%20AGPLv3-blue.svg)](https://github.com/ticgal/borgbase/blob/master/LICENSE)
[![Twitter](https://img.shields.io/badge/Twitter-TICGAL-blue.svg)](https://twitter.com/ticgalcom)
[![TICGAL](https://img.shields.io/badge/Web-TICGAL-blue.svg)](https://tic.gal/)
[![Localazy](https://img.shields.io/badge/Translate-Localazy-cyan)](https://localazy.com/p/mfauth#translations)


# How to use it

Please check the info here: https://tic.gal/en/mfa-for-glpi-does-exactly-what-you-think/

# Scope and limitations

- The plugin adds an e-mailed one-time code to **interactive web logins** (local, LDAP,
  mail server and external authentication, as enabled in its configuration). It is
  enforced on the server for every request, so it also covers SSO/CAS/x509 and
  remember-me logins.
- It does **not** add a second factor to the GLPI REST API (`/apirest.php`) or the
  High-Level API (`/api.php`, including the OAuth password grant). If those channels
  must be covered, disable credential/password login for them and use application
  tokens or the OAuth authorization-code flow instead.
- If a user is covered by GLPI's native 2FA (TOTP), the native factor is used and the
  plugin does not ask for an additional code.
- The per-user lock that protects the attempt rate limiter is a local file lock, so the
  5-attempts-per-15-minutes guarantee holds on a **single node**. A multi-node
  deployment must use a shared cache backend for the rate limiter to be effective
  across nodes.
- The one-time code is stored hashed in the plugin table, but the notification carries
  it in clear text and GLPI keeps the sent notification body in its queue. The queue
  views and APIs mask it, but a reader with direct database access can still read it
  until the row is purged.

# Contribute

Please, fell free to suggest an enhancement of fix via a PR.

# Translations
Translations are handled at Localazy. 

Please head there and add your language: https://localazy.com/p/mfauth

As for GLPI, all translations must use the country code to be accepted.
- fr (Not valid)
- fr_CA (Valid)

All translation contributions are under the [Creative Commons Attribution 4.0 International License](https://spdx.org/licenses/CC-BY-4.0.html)
