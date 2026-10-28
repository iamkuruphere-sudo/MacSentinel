# macOS release signing

The release workflow supports both **Apple Developer ID signed & notarized releases** (for maintainers with a paid Apple Developer membership) and **ad-hoc signed community releases** (for open-source builds without an Apple Developer ID).

## Signing Modes

1. **Community / Open-Source Mode (Default)**:
   - When Apple signing secrets are not present, the workflow builds, packages, and signs the app bundle and DMG with an ad-hoc signature (`codesign --sign -`).
   - The release notes explain that ad-hoc signatures detect file changes but do not establish developer identity or satisfy Gatekeeper. They direct users to Finder's Control-click -> Open flow and do not recommend removing quarantine attributes.
   - This ensures releases and CI runs succeed without requiring a paid Apple Developer account.

2. **Apple Developer ID Mode (Optional)**:
   - When all five Apple secrets are provided, the workflow signs the app with a Developer ID Application certificate, notarizes both the app and disk image with Apple via `xcrun notarytool`, staples Apple's tickets, and verifies Gatekeeper assessment before publishing.

## Optional GitHub Actions secrets (for Apple Notarization)

If you have an active Apple Developer Program account, add these secrets under **Repository Settings → Secrets and variables → Actions**:

| Secret | Value |
|---|---|
| `APPLE_CERTIFICATE_BASE64` | Base64 encoding of a PKCS #12 (`.p12`) export containing a valid **Developer ID Application** certificate and its private key. |
| `APPLE_CERTIFICATE_PASSWORD` | Password used to export that `.p12` file. |
| `APPLE_ID` | Apple Account email authorized for notarization. |
| `APPLE_APP_SPECIFIC_PASSWORD` | App-specific password for that Apple Account. |
| `APPLE_TEAM_ID` | Apple Developer Team ID that owns the certificate. |

Export the Developer ID certificate together with its private key from Keychain Access. Encode the exported file locally (`base64 < DeveloperID.p12 | pbcopy`) and paste the result into `APPLE_CERTIFICATE_BASE64`. Do not commit the certificate, private key, or password to the repository.

Once configured, any new release will automatically be notarized and trusted by macOS Gatekeeper out-of-the-box.
