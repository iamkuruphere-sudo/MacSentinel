# MacSentinel

A native SwiftUI macOS app for collecting a point-in-time, read-only security evidence snapshot. It does not remove files, change settings, install agents, quarantine software, or claim a clean bill of health.

## Checks included

- System Integrity Protection, Gatekeeper, FileVault, enrollment, and hardware/secure-boot related system profile data.
- TCP listeners and current TCP socket table, proxy settings, firewall state, and configured shares.
- Background-task inventory, system and user launch services, system extensions, and configuration profiles.
- Available macOS software updates and code-signature integrity checks for a bounded set of installed application bundles.
- Common launch-agent and launch-daemon folders plus Microsoft Office startup folders, where macro or add-in autoloading may occur.
- Installer history and selected recent macOS Unified Log events related to persistence, privacy permissions, update activity, and code-signing.

The dashboard turns each scan into an evidence-first overview with review counts, category breakdowns, evidence-linked next steps, and expandable command results. Suggestions explain practical settings or verification steps for recognized results; they do not change the Mac automatically, and ambiguous evidence is explicitly presented as something to investigate rather than a malware verdict. It does not calculate a security score or label a device clean.

Items are evidence to inspect, not verdicts. Legitimate software commonly uses launch services, network connections, profiles, privacy permissions, and update helpers. Application signatures are checked for cryptographic integrity; a valid signature does not establish that an app is benign or free of vulnerabilities. The scanner does not perform publisher reputation checks, malware signature matching, CVE-to-version matching, or compare the operating system against a known-good baseline.

Application signature checks recursively inspect application bundles found under `/Applications` and `~/Applications`, up to 100 bundles per scan. The result is a bounded local inventory, not a complete audit of every executable or plugin on the Mac. Unavailable commands, nonzero command exits, timeouts, truncated output, and known directory or scan limits are surfaced as items needing review.

## Logging

The app uses CocoaLumberjack to write its own audit lifecycle events to Unified Logging and a rotating local log file (daily rotation, up to seven files). It also reads selected existing events through Apple's `log show` command. Audit outputs can contain private paths and machine details; JSON export is explicit and saved only to the location the user chooses.

## Build and run

Requires macOS 14 or later. Building from source requires Swift 6.2 or later. For Apple silicon, download `MacSentinel-arm64.dmg` from the [latest GitHub release](https://github.com/iamkuruphere-sudo/MacSentinel/releases/latest), open the disk image, and drag `MacSentinel.app` to Applications. New `v*` tags automatically build and attach the DMG to a GitHub release. A manual run of the **Build Apple silicon DMG** workflow also produces a downloadable Actions artifact.

The downloadable app is built for Apple silicon (`arm64`) and includes the `Resources/MacSentinel.icns` app icon. If an Apple Developer ID certificate is configured in GitHub secrets, releases are notarized by Apple. Community releases without a Developer ID certificate use an ad-hoc signature to detect changes, but are not notarized and may trigger a Gatekeeper warning; this signature does not establish developer identity or make the app trusted by macOS. To try a community build, Control-click the app in Finder and select **Open**; if macOS still blocks it, use **System Settings → Privacy & Security → Open Anyway** only if you trust the download. Do not remove the app's quarantine attributes. To build locally, open this folder in Xcode as a Swift package or run `swift run`; the first build resolves CocoaLumberjack from its official Swift Package Manager source.

## App updates

MacSentinel checks the latest public GitHub Release on launch and every 24 hours while it is open. Use **Updates** in the app to check immediately. When a newer version-tagged release is available, the app downloads its Apple-silicon DMG to `~/Downloads` and verifies the SHA-256 digest reported by GitHub before making the file available to open. It does not replace the running app automatically: open the downloaded DMG, quit MacSentinel, then drag the app into Applications and confirm replacement. Updates are released from version tags; commits that have not been published as a GitHub Release are not offered by the updater.

## Boundaries and limitations

- macOS privacy protections can hide databases and log details unless the app has Full Disk Access or administrator privileges. The report should be read as partial when a command is denied or returns incomplete data.
- User-space checks cannot conclusively validate firmware, detect every spyware implant, or prove there was no unauthorized access. Apple silicon Secure Boot state is not fully exposed by a generic user-space command; hardware-specific verification may require Apple recovery or support tools.
- The Office scan finds files in conventional startup locations. It does not inspect every document for macros and does not infer that an Office macro is malicious.
- The software update check reports updates offered by macOS; it does not determine whether installed third-party software has a known CVE. Signature verification detects integrity/signing problems, not malware or exploitable application vulnerabilities.
- Run the app from a trusted source. This source project is not signed, notarized, or distributed as a hardened runtime application.
- Review evidence with a trusted security professional before deleting or disabling anything.
