# MFA

## 3.0.1-beta.1 - 2026-11-09
## Security
- A session waiting for its code no longer counts as authenticated for anything that reads the session
  (legacy REST API `Session-Token`, high-level API authorisation endpoint): its identity is kept aside by
  the plugin until the code is verified.
- Refuse the sign-in methods that use the password alone and never reach the code form, for the accounts
  that need a code: CalDAV, legacy REST API `initSession` with login and password, and the high-level API
  OAuth `password` grant.
- A TOTP enrolled during the login itself (native 2FA setup step) no longer waives the plugin code: only a
  TOTP that existed before the login does.
## Features
- The configuration cannot turn an authentication type on while codes cannot be delivered (e-mail
  notifications disabled, notification inactive) or while the automatic action that sends the queued
  mails (`queuednotification`) is disabled. Turning a type off is always possible.
- Activating the plugin warns when a stored configuration would lock users out. The configuration tab
  also warns when the queue action has not run for more than a day.
- The code screen tells the user when the mail server refused the code, instead of waiting for a code
  that never arrives; reloading the page tries again.
- New switch for CAS and x509 accounts, which were never asked for a code. Existing installations get it
  set to "No" when the plugin is updated.
- New installations start with every authentication type set to "No".
## Bugfixes
- The code form is shown in normal mode (no debug bar, no rejected debug requests) while a code is pending;
  the debug mode is restored once it is verified.
- Sessions opened before the plugin was activated are no longer sent to the code form right after
  activating it.
- The requested page is kept relative to the GLPI root, so the redirection after the code also works when
  GLPI is served from a sub-directory.
- The automatic action is registered at install time, not on every request.
## Documentation
- README: entry points covered by the plugin, limitations, and how to recover when the plugin folder was
  deleted without uninstalling it.

## 3.0.0 - 2026-10-01
## Feature
- GLPI 12 support

## 2.0.2 - 2026-09-30
## Security
- Fix authentication bypass: the plugin completed the login before asking for the
  security code, so the session was already valid while the code form was displayed
  and any page could be reached without entering the code. Credentials are now
  validated first and the session is only created once the code has been verified,
  using the same pre-authentication mechanism as GLPI native 2FA.
- Do not issue the "remember me" cookie until the security code has been verified.
  It was sent during the first step and survived the logout, allowing a login from
  the login page without the code.
- Bind the security code to the user that passed the first step. Any pending code
  of any user used to validate the login.
- Restore CSRF protection on the login endpoint. It was registered as a stateless
  path, which also exempts it from CSRF checks; it now uses the firewall strategy
  meant for unauthenticated plugin scripts.
- Fix second-factor bypass through operator injection: the submitted code was passed
  raw as a query criterion, so sending it as an array (`code[0]=LIKE&code[1]=%`) made
  GLPI build `code LIKE '%'` and match any pending code. The value is now forced to a
  scalar string before the lookup.
- Rate-limit code verification: 5 failed attempts per user within 15 minutes now lock
  further attempts, closing brute force of the 6-digit code. The counter resets on a
  successful verification.
- Store the security code hashed instead of in clear text, so a read of the table
  during its validity window no longer yields a usable second factor. The plaintext
  only travels in the notification e-mail.
- Enforce code expiration at verification time (10 minutes) instead of relying solely
  on the cleanup cron, and issue a fresh code on every login attempt so a code can no
  longer be reused across attempts. Expiration is compared against the database clock
  to stay correct regardless of the PHP/DB timezone offset.
## Bugfixes
- Fix redirect after the security code: the requested URL was discarded and the user
  always landed on the dashboard. Also honoured now when native 2FA is active or when
  the profile does not require a code, which additionally fixes the landing page for
  simplified interface users.
- Clean up on uninstall: the uninstall routine mistakenly re-ran install and left
  everything behind. It now drops the plugin tables (`glpi_plugin_mfa_mfas`,
  `glpi_plugin_mfa_configs`) and removes the notification, template, translation and
  target it created.

## 2.0.0 - 2026-01-27
- GLPI 11 support

## 1.0.3 - 2024-02-16
## Bugfixes
- Fix redirect

## 1.0.2 - 2023-05-02
## Features
- Twig template for MFA Login #15193
- Update localazy strings (Indonesian)
- Update localazy strings (Netherlands)
## Bugfixes
- Fix save config #13665
- Fix check default authtype #13675
- Fix security problem #15193

## 1.0.1 - 2022-12-26
## Features
- New Galician translation (gl_ES)
## Bugfixes
- Update localazy strings #11027

## 1.0.0
#Features
- New option to select which Auth methods are affected by MFA
- 6-digit OTP Token

## 0.9.0 (Internal)
### Features
- OTP Auth
- OTP Token sent via e-mail
- Expired tokens clean up Automatic Action
