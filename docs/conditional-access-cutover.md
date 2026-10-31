# Cut over from Security Defaults to Conditional Access

This runbook is for a small-business tenant moving to Conditional Access (CA). It describes an operator workflow, not an atomic migration. Have an administrator signed in at the portal before starting. A short gap in MFA enforcement is possible; budget time for recovery as well as activation.

## Pre-flight

- [ ] Confirm Microsoft Entra ID P1 or higher licensing for Conditional Access and the administrative roles needed for the change. See [Conditional Access prerequisites](https://learn.microsoft.com/en-us/entra/identity/conditional-access/overview#license-requirements).
- [ ] Record existing settings, policy scopes, exclusions, and a recovery plan. Verify emergency access before touching enforcement. See [deployment planning](https://learn.microsoft.com/en-us/entra/identity/conditional-access/plan-conditional-access).
- [ ] Stage replacement policies in report-only first, including MFA coverage and blocking legacy authentication. Keep Security Defaults enabled while preparing. Microsoft permits policy creation while Security Defaults is on, but prevents enabling CA at the same time. See [switching MFA controls](https://learn.microsoft.com/en-us/microsoft-365/admin/security-and-compliance/set-up-multi-factor-authentication?view=o365-worldwide).
- [ ] Review report-only results where available and resolve unexpected exclusions. Report-only does not enforce controls, so it is not proof of MFA coverage. See [report-only evaluation](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-report-only).
- [ ] If using sign-in frequency, turn off the legacy remembered-MFA setting below before enabling that policy. Confirm the administrator can carry out the rollback, including policy deletion if required.

## The failure to avoid

The failure behind this runbook was a cutover that disabled Security Defaults and immediately tried to enable CA. Activation failed; attempting to turn Security Defaults back on also failed because CA policies existed. That left a window without MFA enforcement from either control. This is an operational observation, not a Microsoft guarantee that every cutover fails this way.

Microsoft says to activate replacement CA protection immediately after disabling Security Defaults. The read-back and retry procedure below is an operational precaution for the observed failure, not a documented propagation-time guarantee. See [moving from Security Defaults](https://learn.microsoft.com/en-us/entra/fundamentals/security-defaults#move-from-security-defaults-to-conditional-access).

## Cutover procedure

1. Keep the administrator at the portal and the policy inventory ready. Disable Security Defaults and save.
2. Poll its state until it reads disabled. An automated read can use `GET /v1.0/policies/identitySecurityDefaultsEnforcementPolicy`; require `isEnabled` to be `false`. A failed read is an unknown state, not confirmation. Set a deadline and poll interval before starting. See the [Security Defaults read API](https://learn.microsoft.com/en-us/graph/api/identitysecuritydefaultsenforcementpolicy-get?view=graph-rest-1.0).
3. Enable each replacement policy, beginning with the MFA policies. Read each policy back after the update; a successful request alone does not prove the intended sign-in is protected. The [CA update API](https://learn.microsoft.com/en-us/graph/api/conditionalaccesspolicy-update?view=graph-rest-1.0) changes policy properties; the [policy resource](https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccesspolicy?view=graph-rest-1.0) defines `enabled`, `disabled`, and `enabledForReportingButNotEnforced` states.
4. Retry transient activation failures with a bounded attempt count and exponential backoff. Honor `Retry-After` on throttled requests. Do not repeatedly retry permission or validation failures without correction. See [Graph retry guidance](https://learn.microsoft.com/en-us/graph/throttling#best-practices-to-handle-throttling).
5. Log each attempt's outcome and a redacted error body. Remove tokens, account details, tenant identifiers, and sensitive request data before persisting it. If safe redaction is uncertain, retain only status and a generic error category. At the deadline, stop automatic retries and have the portal administrator execute the prepared recovery plan.

## Rollback order

First return the changed CA policies to report-only or off and verify their states. That alone is not a complete rollback to Security Defaults. Microsoft's current instructions say CA policies in any state prevent enabling Security Defaults. Record their settings, delete all existing CA policies as part of the prepared recovery plan, then re-enable Security Defaults and read its state back. See [reverting to Security Defaults](https://learn.microsoft.com/en-us/microsoft-365/admin/security-and-compliance/set-up-multi-factor-authentication?view=o365-worldwide#revert-to-security-defaults-from-conditional-access-policies).

Do not call recovery complete because policies are off. Verify restored protection with sign-in checks. Policy deletion and re-enablement extend the possible gap, so an administrator must be ready before the first change.

## The setting that is easy to miss

Before enabling a sign-in frequency policy, disable legacy "Remember MFA on trusted devices". Microsoft warns that combining them can cause unexpected prompts. See [session lifetime prerequisites](https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-session-lifetime#overview).

This is a portal-only step in this runbook: Entra ID > Multifactor authentication > Additional cloud-based MFA settings > Service settings. Some portal layouts place the additional-settings link under Getting started > Configure. Clear "Allow users to remember multifactor authentication on devices they trust", then save. Microsoft's [MFA service settings guide](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-mfa-mfasettings#mfa-service-settings) documents the legacy portal and an alternate route through Users > Per-user MFA > Service settings. No automation for this setting is claimed here.

The observed symptom was unexpected re-prompts and repeated "MFA expired" refresh failures in mobile mail clients, with error 50078. Microsoft defines `AADSTS50078` as expired MFA requiring refresh in its [error reference](https://learn.microsoft.com/en-us/entra/identity-platform/reference-error-codes). That code alone does not establish this setting as the cause. Inspect the applied session policies and the client sign-in details before diagnosing it. Microsoft also describes increased client authentication requests from remembered MFA in [reauthentication and session lifetime](https://learn.microsoft.com/en-us/entra/identity/authentication/concepts-azure-multi-factor-authentication-prompts-session-lifetime#option-to-remember-multifactor-authentication).

## Post-flight

- [ ] Confirm Security Defaults is disabled and every intended replacement policy is enabled, or confirm Security Defaults is enabled after rollback.
- [ ] Test a fresh browser sign-in and a mobile mail session, including a refresh after the configured sign-in frequency interval.
- [ ] Check sign-in logs for expected policy application, intended exclusions, and unexpected repeated MFA prompts. Use the [report-only evaluation guide](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-report-only) to distinguish simulated results from enforced results.
- [ ] Record the final policy states, any enforcement gap, test outcomes, and unresolved client failures without storing sensitive error data.
