# MacSentinel

A native SwiftUI macOS app for collecting a point-in-time, read-only security evidence snapshot. It does not remove files, change settings, install agents, quarantine software, or claim a clean bill of health.

## Checks included

- System Integrity Protection, Gatekeeper, FileVault, enrollment, and hardware/secure-boot related system profile data.
- TCP listeners and current TCP socket table, proxy settings, firewall state, and configured shares.
- Background-task inventory, system and user launch services, system extensions, and configuration profiles.
- Common launch-agent and launch-daemon folders plus Microsoft Office startup folders, where macro or add-in autoloading may occur.
- Installer history and selected recent macOS Unified Log events related to persistence, privacy permissions, update activity, and code-signing.

Items are evidence to inspect, not verdicts. Legitimate software commonly uses launch services, network connections, profiles, privacy permissions, and update helpers. The starter scanner gathers inventories and raw logs; it does not yet perform publisher reputation checks, malware signature matching, or compare the operating system against a known-good baseline.

## Logging

The app uses CocoaLumberjack to write its own audit lifecycle events to Unified Logging and a rotating local log file (daily rotation, up to seven files). It also reads selected existing events through Apple's `log show` command. Audit outputs can contain private paths and machine details; JSON export is explicit and saved only to the location the user chooses.

## Build and run

The locally built app bundle is `MacSentinel.app`. Open it from Finder to run the scan. The bundle is ad-hoc signed for local use, not Developer ID signed or notarized. To rebuild, open this folder in Xcode as a Swift package or run `swift run` from this directory. The first build resolves CocoaLumberjack from its official Swift Package Manager source. Requires macOS 14 or later.

## Boundaries and limitations

- macOS privacy protections can hide databases and log details unless the app has Full Disk Access or administrator privileges. The report should be read as partial when a command is denied or returns incomplete data.
- User-space checks cannot conclusively validate firmware, detect every spyware implant, or prove there was no unauthorized access. Apple silicon Secure Boot state is not fully exposed by a generic user-space command; hardware-specific verification may require Apple recovery or support tools.
- The Office scan finds files in conventional startup locations. It does not inspect every document for macros and does not infer that an Office macro is malicious.
- Run the app from a trusted source. This source project is not signed, notarized, or distributed as a hardened runtime application.
- Review evidence with a trusted security professional before deleting or disabling anything.
