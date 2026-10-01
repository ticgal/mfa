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

Notes: the code is always asked for on a new session, including when it is restored from a "remember me"
cookie. REST API tokens and other flows that do not use the web session are not covered by the plugin.

# Contribute

Please, fell free to suggest an enhancement of fix via a PR.

# Translations
Translations are handled at Localazy. 

Please head there and add your language: https://localazy.com/p/mfauth

As for GLPI, all translations must use the country code to be accepted.
- fr (Not valid)
- fr_CA (Valid)

All translation contributions are under the [Creative Commons Attribution 4.0 International License](https://spdx.org/licenses/CC-BY-4.0.html)
