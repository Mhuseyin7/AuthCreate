# Scenarios

| Preset | Protocol behavior |
|---|---|
| `happy-path` | Normal flow |
| `mfa-required` | Deterministic MFA challenge; development code `123456` |
| `expired-session` | Authorization returns `login_required` |
| `scope-denied` | Authorization returns `invalid_scope` |
| `provider-down` | Authorization returns `temporarily_unavailable` |
| `slow-provider` | Adds two seconds before the token response |
| `refresh-expired` | Refresh exchange returns `invalid_grant` |

Scenarios change protocol behavior; they are not cosmetic UI toggles. Scenario state is process-local in this initial development deployment.
