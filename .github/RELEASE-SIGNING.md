# macOS release signing

The release workflow signs the app with a Developer ID Application certificate, notarizes both the app and disk image with Apple, staples Apple's tickets, and verifies Gatekeeper acceptance before publishing. Release builds intentionally fail rather than falling back to an ad-hoc signature.

## Required GitHub Actions secrets

Add these secrets under **Repository Settings → Secrets and variables → Actions**:

| Secret | Value |
|---|---|
| `APPLE_CERTIFICATE_BASE64` | Base64 encoding of a PKCS #12 (`.p12`) export containing a valid **Developer ID Application** certificate and its private key. |
| `APPLE_CERTIFICATE_PASSWORD` | Password used to export that `.p12` file. |
| `APPLE_ID` | Apple Account email authorized for notarization. |
| `APPLE_APP_SPECIFIC_PASSWORD` | App-specific password for that Apple Account. |
| `APPLE_TEAM_ID` | Apple Developer Team ID that owns the certificate. |

Export the Developer ID certificate together with its private key from Keychain Access. Encode the exported file locally (for example, `base64 < DeveloperID.p12 | pbcopy`) and paste the result directly into the `APPLE_CERTIFICATE_BASE64` secret. Do not commit the certificate, private key, password, or encoded certificate to the repository or paste them into an issue or chat.

After adding all five secrets, run **Actions → Build Apple silicon DMG → Run workflow** to test a notarized artifact, or push a new `v*` tag to create a GitHub release. The workflow verifies the signature, notarization ticket, disk image, and Gatekeeper assessment before uploading anything.

The previously published releases were signed ad hoc and are not notarized. They cannot be made trusted by changing their existing files or tags; publish a new version after configuring these secrets.
