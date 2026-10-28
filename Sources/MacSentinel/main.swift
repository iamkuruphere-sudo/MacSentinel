import SwiftUI
import AppKit
import Darwin
import Charts
import CryptoKit
import OSLog
import CocoaLumberjackSwift
import Security

@MainActor private let auditLog = Logger(subsystem: "local.macsentinel", category: "audit")

private func configureLogging() {
    DDLog.add(DDOSLogger.sharedInstance)
    let fileLogger = DDFileLogger()
    fileLogger.rollingFrequency = 60 * 60 * 24
    fileLogger.logFileManager.maximumNumberOfLogFiles = 7
    DDLog.add(fileLogger)
}

struct Evidence: Identifiable, Codable, Sendable {
    var id = UUID()
    let category: String
    let title: String
    let detail: String
    let level: Level
    let guidance: ScanGuidance?
    enum Level: String, Codable, Sendable { case info, review, concern }
}

struct ScanGuidance: Codable, Sendable {
    let summary: String
    let steps: [String]

    static func assess(
        title: String,
        detail: String,
        level: Evidence.Level
    ) -> (level: Evidence.Level, guidance: ScanGuidance?) {
        let output = detail.lowercased()
        let hasIncompleteMarker = [
            "unavailable:",
            "[timed out;",
            "[command exited with status",
            "[command output capture limited",
            "[output stream did not close"
        ].contains { output.contains($0) }

        switch title {
        case "System Integrity Protection" where output.contains("status: disabled"):
            return (
                .concern,
                ScanGuidance(
                    summary: "System Integrity Protection is reported as disabled. This reduces macOS protection for system files and processes.",
                    steps: [
                        "If you did not intentionally disable it, restart into macOS Recovery. On Apple silicon, hold the power button until startup options appear and choose Options; on Intel, restart while holding Command-R.",
                        "In Recovery, open Utilities > Terminal, run `csrutil enable`, then restart and run the scan again. Check with your administrator first on a managed Mac."
                    ]
                )
            )
        case "Gatekeeper assessment" where output.contains("assessments disabled"):
            return (
                .concern,
                ScanGuidance(
                    summary: "Gatekeeper assessments are reported as disabled, so macOS may not apply its normal checks to downloaded apps.",
                    steps: [
                        "Open System Settings > Privacy & Security and set downloaded-app protection to App Store and identified developers.",
                        "Rerun the scan. Do not bypass a warning for an app you cannot verify with its publisher."
                    ]
                )
            )
        case "FileVault" where output.contains("filevault is off"):
            return (
                .concern,
                ScanGuidance(
                    summary: "FileVault is reported as off, so data on this Mac may not be protected by full-disk encryption.",
                    steps: [
                        "Open System Settings > Privacy & Security > FileVault and choose Turn On.",
                        "Save the recovery method offered during setup somewhere separate from this Mac, then rerun the scan. Check with your administrator first on a managed Mac."
                    ]
                )
            )
        case "Firewall status" where output.contains("firewall is disabled") || output.contains("firewall is not enabled"):
            return (
                .concern,
                ScanGuidance(
                    summary: "The macOS application firewall is reported as disabled.",
                    steps: [
                        "Open System Settings > Network > Firewall and turn it on.",
                        "Review Firewall Options for your sharing needs; avoid enabling “Block all incoming connections” unless you understand the impact."
                    ]
                )
            )
        case "Remote login service" where output.contains("remote login: on"):
            return (
                .review,
                ScanGuidance(
                    summary: "Remote Login (SSH) is enabled. Keep it on only if you use remote administration.",
                    steps: [
                        "If you do not need SSH access, open System Settings > General > Sharing > Remote Login and turn it off.",
                        "If you do need it, restrict “Allow access for” to the specific accounts that require access and confirm the setting with your administrator on a managed Mac."
                    ]
                )
            )
        case "Available macOS software updates"
            where output.contains("software update found the following") || output.contains("* label:"):
            return (
                .review,
                ScanGuidance(
                    summary: "macOS reports one or more updates. The scan does not determine whether an update addresses a vulnerability.",
                    steps: [
                        "Open System Settings > General > Software Update and review the offered updates.",
                        "Back up important data, install updates appropriate for this Mac, restart if requested, then rerun the scan."
                    ]
                )
            )
        case "Application scan limit":
            return (
                .review,
                ScanGuidance(
                    summary: "The application-signature inventory stopped at its 100-app limit; additional apps were not checked.",
                    steps: [
                        "Treat the application-signature results as partial, especially if you have many installed apps.",
                        "Review apps outside the listed scan results in Finder and verify unfamiliar apps with their publishers before opening or removing them."
                    ]
                )
            )
        case "Application scan coverage":
            return (
                .review,
                ScanGuidance(
                    summary: "One or more application folders could not be enumerated, so signature coverage is incomplete.",
                    steps: [
                        "Check the folder paths shown below and whether your account is expected to have access.",
                        "If the folder is managed or protected, ask your administrator to confirm coverage rather than changing its permissions."
                    ]
                )
            )
        default:
            break
        }

        if title.localizedCaseInsensitiveContains("code signature"),
           output.contains("signature missing or invalid") || output.contains("could not inspect code signature") {
            return (
                .review,
                ScanGuidance(
                    summary: "The app's signature could not be verified. This does not by itself prove the app is malicious.",
                    steps: [
                        "If you recognize the app, download a fresh copy from the developer's official source and verify it again.",
                        "If you do not recognize it, do not open it. Confirm its publisher and ownership first; use the developer's uninstaller if you decide it should be removed."
                    ]
                )
            )
        }

        if title == "Launch agents, daemons, and Office startup files",
           detail.contains(" | modified ") || detail.contains("Name heuristic:") {
            return (
                .review,
                ScanGuidance(
                    summary: "Startup locations contain entries to review; legitimate apps also use these locations.",
                    steps: [
                        "For an unfamiliar `.plist`, inspect its `Label`, `Program`, and `ProgramArguments` and confirm which installed app owns it. For Office startup files, verify the publisher and expected macro or add-in.",
                        "If an entry belongs to software you do not want, use that software's official uninstaller or disable its login item in System Settings > General > Login Items. Do not delete files based only on their names."
                    ]
                )
            )
        }

        if title == "Nonstandard boot arguments",
           !output.isEmpty,
           !output.contains("data was not found"),
           !output.contains("error getting variable") {
            return (
                .review,
                ScanGuidance(
                    summary: "Boot arguments are configured. They can be intentional, but unexpected values deserve verification.",
                    steps: [
                        "Compare the values below with changes you or your administrator intentionally made.",
                        "If you cannot account for them, ask your administrator or Apple Support to review them before changing boot settings."
                    ]
                )
            )
        }

        if hasIncompleteMarker {
            return (
                .review,
                ScanGuidance(
                    summary: "This check did not collect complete evidence; it is not a security verdict.",
                    steps: [
                        "Read the command output below to identify whether the check timed out, was denied, or failed.",
                        "Rerun the scan after closing unusually busy apps. If access is denied, use your Mac administrator or device manager to confirm whether the check is expected to be restricted."
                    ]
                )
            )
        }

        guard level != .info else { return (level, nil) }
        return (
            level,
            ScanGuidance(
                summary: "This item needs context; the available evidence does not establish that it is malicious.",
                steps: [
                    "Read the collected output below and compare it with software and settings you expect on this Mac.",
                    "If you cannot identify the owner or purpose, confirm with the software publisher or your administrator before disabling or removing anything."
                ]
            )
        )
    }
}

struct AuditReport: Codable {
    let generatedAt: Date
    let host: String
    let macOS: String
    let evidence: [Evidence]
    let limitations: [String]
}

struct EvidenceCategory: Identifiable {
    let name: String
    let count: Int
    let reviewCount: Int
    var id: String { name }
}

@MainActor
final class AuditModel: ObservableObject {
    @Published var running = false
    @Published var evidence: [Evidence] = []
    @Published var lastRun: Date?
    @Published var error: String?
    @Published var selectedCategory: String?

    var reviewCount: Int {
        evidence.filter { $0.level != .info }.count
    }

    var concernCount: Int {
        evidence.filter { $0.level == .concern }.count
    }

    var categories: [EvidenceCategory] {
        Dictionary(grouping: evidence, by: \.category)
            .map { name, items in
                EvidenceCategory(
                    name: name,
                    count: items.count,
                    reviewCount: items.filter { $0.level != .info }.count
                )
            }
            .sorted {
                $0.count == $1.count
                    ? $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending
                    : $0.count > $1.count
            }
    }

    var visibleEvidence: [Evidence] {
        let filtered = selectedCategory.map { category in evidence.filter { $0.category == category } } ?? evidence
        return filtered.sorted {
            if $0.level != $1.level { return $0.level.sortOrder > $1.level.sortOrder }
            if $0.category != $1.category { return $0.category < $1.category }
            return $0.title < $1.title
        }
    }

    var reviewEvidence: [Evidence] {
        evidence
            .filter { $0.level != .info }
            .sorted {
                if $0.level != $1.level { return $0.level == .concern }
                if $0.category != $1.category { return $0.category < $1.category }
                return $0.title < $1.title
            }
    }

    func run() {
        guard !running else { return }
        running = true
        error = nil
        selectedCategory = nil
        DDLogInfo("Read-only endpoint audit started")
        auditLog.notice("Read-only endpoint audit started")
        Task.detached(priority: .userInitiated) {
            let findings = Scanner().scan()
            await MainActor.run {
                self.evidence = findings
                self.lastRun = Date()
                self.running = false
                DDLogInfo("Audit finished with \(findings.count) evidence items")
                auditLog.notice("Audit finished with \(findings.count) evidence items")
            }
        }
    }

    func export() {
        let report = AuditReport(generatedAt: lastRun ?? Date(), host: Host.current().localizedName ?? "Mac",
                                 macOS: ProcessInfo.processInfo.operatingSystemVersionString,
                                 evidence: evidence, limitations: Scanner.limitations)
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "MacSentinel-Evidence-\(ISO8601DateFormatter().string(from: report.generatedAt).prefix(10)).json"
        panel.allowedContentTypes = [.json]
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            let encoder = JSONEncoder(); encoder.outputFormatting = [.prettyPrinted, .sortedKeys]; encoder.dateEncodingStrategy = .iso8601
            try encoder.encode(report).write(to: url, options: .atomic)
            DDLogInfo("Evidence report exported")
            auditLog.notice("Evidence report exported")
        } catch { self.error = "Could not save report: \(error.localizedDescription)" }
    }
}

@MainActor
final class UpdateModel: ObservableObject {
    enum Status: Equatable {
        case idle
        case checking
        case downloading(String)
        case upToDate(String)
        case downloaded(version: String, url: URL)
        case failed(String)
    }

    @Published private(set) var status: Status = .idle
    private var automaticCheckTask: Task<Void, Never>?
    private var downloadedVersion: String?
    private var downloadedURL: URL?

    private static let currentVersionFallback = "0.1.12"
    private static let latestReleaseURL = URL(string: "https://api.github.com/repos/iamkuruphere-sudo/MacSentinel/releases/latest")!
    private static let dmgName = "MacSentinel-arm64.dmg"

    private var currentVersion: String {
        Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? Self.currentVersionFallback
    }

    var isBusy: Bool {
        switch status {
        case .checking, .downloading: true
        default: false
        }
    }

    var buttonTitle: String {
        switch status {
        case .checking: "Checking…"
        case .downloading: "Downloading…"
        default: "Updates"
        }
    }

    func startAutomaticChecks() {
        guard automaticCheckTask == nil else { return }
        automaticCheckTask = Task { [weak self] in
            await self?.checkForUpdates()
            while !Task.isCancelled {
                do {
                    try await Task.sleep(for: .seconds(86_400))
                } catch {
                    return
                }
                await self?.checkForUpdates()
            }
        }
    }

    func checkManually() {
        Task { await checkForUpdates() }
    }

    func dismissStatus() {
        guard !isBusy else { return }
        status = .idle
    }

    func openDownloadedDMG(at url: URL) {
        guard NSWorkspace.shared.open(url) else {
            status = .failed("The downloaded DMG is at \(url.path), but macOS could not open it.")
            return
        }
    }

    private func checkForUpdates() async {
        guard !isBusy else { return }
        status = .checking

        do {
            var request = URLRequest(url: Self.latestReleaseURL, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 20)
            request.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
            request.setValue("MacSentinel", forHTTPHeaderField: "User-Agent")
            let (data, response) = try await URLSession.shared.data(for: request)
            guard let httpResponse = response as? HTTPURLResponse, httpResponse.statusCode == 200 else {
                throw UpdateError.releaseLookupFailed
            }

            let release = try JSONDecoder().decode(GitHubRelease.self, from: data)
            let version = release.tagName.hasPrefix("v") ? String(release.tagName.dropFirst()) : release.tagName
            guard Self.versionComponents(version) != nil else { throw UpdateError.invalidVersion }

            guard Self.isNewer(version, than: currentVersion) else {
                status = .upToDate(currentVersion)
                return
            }

            if downloadedVersion == version,
               let downloadedURL,
               FileManager.default.fileExists(atPath: downloadedURL.path) {
                status = .downloaded(version: version, url: downloadedURL)
                return
            }

            guard let asset = release.assets.first(where: { $0.name == Self.dmgName }) else {
                throw UpdateError.releaseAssetMissing
            }
            status = .downloading(version)
            let url = try await download(asset, version: version)
            downloadedVersion = version
            downloadedURL = url
            status = .downloaded(version: version, url: url)
            auditLog.notice("Downloaded MacSentinel update \(version)")
        } catch {
            status = .failed(error.localizedDescription)
            auditLog.error("Update check failed: \(error.localizedDescription, privacy: .public)")
        }
    }

    private func download(_ asset: GitHubRelease.Asset, version: String) async throws -> URL {
        guard let components = URLComponents(string: asset.downloadURL),
              components.scheme == "https",
              components.host == "github.com",
              components.path.hasPrefix("/iamkuruphere-sudo/MacSentinel/releases/download/"),
              let digest = asset.digest?.lowercased(),
              digest.hasPrefix("sha256:") else {
            throw UpdateError.invalidReleaseAsset
        }
        let expectedDigest = String(digest.dropFirst("sha256:".count))
        guard expectedDigest.count == 64, expectedDigest.allSatisfy(\.isHexDigit) else {
            throw UpdateError.invalidReleaseAsset
        }
        guard let downloadURL = components.url else { throw UpdateError.invalidReleaseAsset }

        var request = URLRequest(url: downloadURL, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 180)
        request.setValue("application/octet-stream", forHTTPHeaderField: "Accept")
        request.setValue("MacSentinel", forHTTPHeaderField: "User-Agent")
        let (temporaryURL, response) = try await URLSession.shared.download(for: request)
        guard let httpResponse = response as? HTTPURLResponse, httpResponse.statusCode == 200 else {
            throw UpdateError.downloadFailed
        }

        let digestData = try Data(contentsOf: temporaryURL, options: [.mappedIfSafe])
        let actualDigest = SHA256.hash(data: digestData).map { String(format: "%02x", $0) }.joined()
        guard actualDigest == expectedDigest else { throw UpdateError.checksumMismatch }

        let downloads = FileManager.default.urls(for: .downloadsDirectory, in: .userDomainMask).first
            ?? FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Downloads", isDirectory: true)
        try FileManager.default.createDirectory(at: downloads, withIntermediateDirectories: true)

        var destination = downloads.appendingPathComponent("MacSentinel-\(version)-arm64.dmg")
        if FileManager.default.fileExists(atPath: destination.path) {
            let existingData = try Data(contentsOf: destination, options: [.mappedIfSafe])
            let existingDigest = SHA256.hash(data: existingData).map { String(format: "%02x", $0) }.joined()
            if existingDigest == expectedDigest {
                try FileManager.default.removeItem(at: temporaryURL)
                return destination
            }
            destination = downloads.appendingPathComponent("MacSentinel-\(version)-arm64-\(UUID().uuidString.prefix(8)).dmg")
        }
        try FileManager.default.moveItem(at: temporaryURL, to: destination)
        return destination
    }

    private static func versionComponents(_ version: String) -> [Int]? {
        let parts = version.split(separator: ".", omittingEmptySubsequences: false)
        guard (2...3).contains(parts.count) else { return nil }
        let values = parts.compactMap { Int($0) }
        guard values.count == parts.count, parts.allSatisfy({ $0.allSatisfy(\.isNumber) }) else { return nil }
        return values
    }

    private static func isNewer(_ candidate: String, than current: String) -> Bool {
        guard let candidateParts = versionComponents(candidate),
              let currentParts = versionComponents(current) else { return false }
        for index in 0..<max(candidateParts.count, currentParts.count) {
            let candidatePart = index < candidateParts.count ? candidateParts[index] : 0
            let currentPart = index < currentParts.count ? currentParts[index] : 0
            if candidatePart != currentPart { return candidatePart > currentPart }
        }
        return false
    }

    private struct GitHubRelease: Decodable {
        let tagName: String
        let assets: [Asset]

        enum CodingKeys: String, CodingKey {
            case tagName = "tag_name"
            case assets
        }

        struct Asset: Decodable {
            let name: String
            let downloadURL: String
            let digest: String?

            enum CodingKeys: String, CodingKey {
                case name
                case downloadURL = "browser_download_url"
                case digest
            }
        }
    }

    private enum UpdateError: LocalizedError {
        case releaseLookupFailed
        case invalidVersion
        case releaseAssetMissing
        case invalidReleaseAsset
        case downloadFailed
        case checksumMismatch

        var errorDescription: String? {
            switch self {
            case .releaseLookupFailed: "GitHub did not return a valid latest-release response."
            case .invalidVersion: "The latest GitHub release has an unsupported version tag."
            case .releaseAssetMissing: "The latest release does not contain the Apple-silicon DMG."
            case .invalidReleaseAsset: "The release asset URL or SHA-256 digest is missing or invalid."
            case .downloadFailed: "GitHub did not return the DMG successfully."
            case .checksumMismatch: "The downloaded DMG did not match GitHub's published SHA-256 digest."
            }
        }
    }
}

struct Scanner {
    static let limitations = [
        "This is a read-only triage scan, not an antivirus engine or proof that a Mac is clean.",
        "Some system databases and protected logs require Full Disk Access or administrator approval; inaccessible data is reported as limited.",
        "Firmware integrity and spyware cannot be conclusively established by a user-space scan. Use Apple Diagnostics and trusted Apple recovery/reinstall workflows for deeper validation.",
        "A file name, unsigned component, remote connection, or privacy permission can be legitimate. Review context before acting."
    ]

    private final class BoundedCapture: @unchecked Sendable {
        private let lock = NSLock()
        private var bytes = Data()
        private let limit = 65_536
        private var truncated = false

        func append(_ chunk: Data) {
            guard !chunk.isEmpty else { return }
            lock.lock(); defer { lock.unlock() }
            let remaining = limit - bytes.count
            if remaining > 0 { bytes.append(chunk.prefix(remaining)) }
            if chunk.count > remaining { truncated = true }
        }

        func result() -> (Data, Bool) {
            lock.lock(); defer { lock.unlock() }
            return (bytes, truncated)
        }
    }

    private struct CommandResult {
        let text: String
        let isComplete: Bool
    }

    private func command(_ path: String, _ args: [String] = [], timeout: TimeInterval = 18) -> CommandResult {
        let p = Process(); p.executableURL = URL(fileURLWithPath: path); p.arguments = args
        let out = Pipe(); let capture = BoundedCapture()
        let outputClosed = DispatchSemaphore(value: 0)
        p.standardOutput = out; p.standardError = out
        out.fileHandleForReading.readabilityHandler = { handle in
            let chunk = handle.availableData
            if chunk.isEmpty {
                handle.readabilityHandler = nil
                outputClosed.signal()
            } else {
                capture.append(chunk)
            }
        }
        do {
            try p.run()
            // Close the parent's write end so the reader receives EOF after the child exits.
            try? out.fileHandleForWriting.close()
            let deadline = Date().addingTimeInterval(timeout)
            while p.isRunning && Date() < deadline { Thread.sleep(forTimeInterval: 0.1) }
            let timedOut = p.isRunning
            if timedOut {
                p.terminate()
                let terminationDeadline = Date().addingTimeInterval(1)
                while p.isRunning && Date() < terminationDeadline { Thread.sleep(forTimeInterval: 0.1) }
                if p.isRunning { _ = kill(p.processIdentifier, SIGKILL) }
                p.waitUntilExit()
            }
            let outputWasDrained = outputClosed.wait(timeout: .now() + 1) == .success
            out.fileHandleForReading.readabilityHandler = nil
            try? out.fileHandleForReading.close()
            let (data, truncated) = capture.result()
            var text = String(decoding: data, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
            if truncated { text += "\n[Command output capture limited to 64 KB.]" }
            if timedOut { text += "\n[Timed out; output may be incomplete.]" }
            if !outputWasDrained { text += "\n[Output stream did not close before the read deadline; output may be incomplete.]" }
            if !timedOut && p.terminationStatus != 0 {
                text += "\n[Command exited with status \(p.terminationStatus).]"
            }
            return CommandResult(text: text, isComplete: !timedOut && !truncated && outputWasDrained && p.terminationStatus == 0)
        } catch {
            return CommandResult(text: "Unavailable: \(error.localizedDescription)", isComplete: false)
        }
    }

    private func add(_ out: inout [Evidence], _ category: String, _ title: String, _ result: CommandResult, _ level: Evidence.Level = .info) {
        add(&out, category, title, result.text, result.isComplete ? level : .review)
    }

    private func add(_ out: inout [Evidence], _ category: String, _ title: String, _ detail: String, _ level: Evidence.Level = .info) {
        let shown = detail.isEmpty ? "No output returned." : String(detail.prefix(5000))
        let clipped = detail.count > 5000 ? "\n[Display limited to 5,000 characters.]" : ""
        let assessment = ScanGuidance.assess(title: title, detail: shown + clipped, level: level)
        out.append(Evidence(
            category: category,
            title: title,
            detail: shown + clipped,
            level: assessment.level,
            guidance: assessment.guidance
        ))
    }

    func scan() -> [Evidence] {
        var e: [Evidence] = []
        add(&e, "System integrity", "System Integrity Protection", command("/usr/bin/csrutil", ["status"]))
        add(&e, "System integrity", "Gatekeeper assessment", command("/usr/sbin/spctl", ["--status"]))
        add(&e, "System integrity", "Sealed system volume", command("/usr/bin/csrutil", ["authenticated-root", "status"]))
        add(&e, "System integrity", "Nonstandard boot arguments", command("/usr/sbin/nvram", ["boot-args"]))
        add(&e, "System integrity", "FileVault", command("/usr/bin/fdesetup", ["status"]))
        add(&e, "System integrity", "Device management enrollment", command("/usr/bin/profiles", ["status", "-type", "enrollment"]))
        add(&e, "System integrity", "Secure boot and hardware overview", command("/usr/sbin/system_profiler", ["SPiBridgeDataType", "SPHardwareDataType", "-detailLevel", "mini"], timeout: 35))
        add(&e, "Network", "Listening TCP services", command("/usr/sbin/lsof", ["-nP", "-iTCP", "-sTCP:LISTEN"], timeout: 25))
        add(&e, "Network", "Current network connections", command("/usr/sbin/netstat", ["-an", "-p", "tcp"]))
        add(&e, "Network", "Sharing configuration", command("/usr/sbin/sharing", ["-l"]))
        add(&e, "Monitoring", "Remote login service", command("/usr/sbin/systemsetup", ["-getremotelogin"]))
        add(&e, "Persistence", "Background items", command("/usr/bin/sfltool", ["dumpbtm"], timeout: 25))
        add(&e, "Persistence", "System launch services", command("/bin/launchctl", ["list"], timeout: 25))
        add(&e, "Persistence", "User launch services", command("/bin/launchctl", ["list", "gui/\(getuid())"], timeout: 25))
        add(&e, "Monitoring", "System extensions", command("/usr/bin/systemextensionsctl", ["list"]))
        add(&e, "Monitoring", "Configuration profiles", command("/usr/bin/profiles", ["list", "-type", "configuration"]))
        add(&e, "Updates", "Recent installer history", command("/usr/sbin/system_profiler", ["SPInstallHistoryDataType", "-detailLevel", "mini"], timeout: 35))
        add(&e, "Updates", "Available macOS software updates", command("/usr/sbin/softwareupdate", ["--list"], timeout: 60))
        add(&e, "Logs", "Recent security and persistence log events", command("/usr/bin/log", ["show", "--last", "24h", "--style", "compact", "--info", "--predicate", "(eventMessage CONTAINS[c] 'launch' OR eventMessage CONTAINS[c] 'login item' OR eventMessage CONTAINS[c] 'screen recording' OR eventMessage CONTAINS[c] 'microphone' OR eventMessage CONTAINS[c] 'camera' OR eventMessage CONTAINS[c] 'profile' OR eventMessage CONTAINS[c] 'software update' OR eventMessage CONTAINS[c] 'amfi' OR eventMessage CONTAINS[c] 'signature')"], timeout: 35))
        scanStartupFiles(into: &e)
        scanInstalledApplications(into: &e)
        add(&e, "Network", "Proxy settings", command("/usr/sbin/scutil", ["--proxy"]))
        add(&e, "System integrity", "Firewall status", command("/usr/libexec/ApplicationFirewall/socketfilterfw", ["--getglobalstate"]))
        return e
    }

    private func scanInstalledApplications(into e: inout [Evidence]) {
        let roots = [
            URL(fileURLWithPath: "/Applications", isDirectory: true),
            FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Applications", isDirectory: true)
        ]
        let maximumApplications = 100
        var scanned = 0
        var limited = false
        var inaccessibleRoots: [String] = []

        for root in roots {
            guard FileManager.default.fileExists(atPath: root.path) else { continue }
            guard let enumerator = FileManager.default.enumerator(
                at: root,
                includingPropertiesForKeys: nil,
                options: [.skipsHiddenFiles]
            ) else {
                inaccessibleRoots.append(root.path)
                continue
            }

            while let url = enumerator.nextObject() as? URL {
                guard url.pathExtension.caseInsensitiveCompare("app") == .orderedSame else { continue }
                enumerator.skipDescendants()
                if scanned == maximumApplications {
                    limited = true
                    break
                }
                scanned += 1

                var staticCode: SecStaticCode?
                let createStatus = SecStaticCodeCreateWithPath(url as CFURL, SecCSFlags(), &staticCode)
                guard createStatus == errSecSuccess, let staticCode else {
                    add(&e, "Application integrity", "\(url.deletingPathExtension().lastPathComponent) code signature",
                        "\(url.path)\nCould not inspect code signature (OSStatus \(createStatus)).", .review)
                    continue
                }

                let verificationStatus = SecStaticCodeCheckValidity(
                    staticCode,
                    SecCSFlags(rawValue: kSecCSCheckAllArchitectures | kSecCSStrictValidate),
                    nil
                )
                var signingInformation: CFDictionary?
                _ = SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &signingInformation)
                let info = signingInformation as? [String: Any] ?? [:]
                let identifier = info[kSecCodeInfoIdentifier as String] as? String ?? "unknown"
                let teamIdentifier = info[kSecCodeInfoTeamIdentifier as String] as? String ?? "none"
                let isValid = verificationStatus == errSecSuccess
                let statusText = isValid ? "Signature integrity valid" : "Signature missing or invalid (OSStatus \(verificationStatus))"
                let detail = "\(url.path)\n\(statusText)\nIdentifier: \(identifier)\nTeam ID: \(teamIdentifier)\nA valid signature does not establish that an app is vulnerability-free or benign."
                add(&e, "Application integrity", "\(url.deletingPathExtension().lastPathComponent) code signature", detail, isValid ? .info : .review)
            }
            if limited { break }
        }

        if scanned == 0 {
            add(&e, "Application integrity", "Installed application signatures",
                "No application bundles were found in /Applications or ~/Applications.", inaccessibleRoots.isEmpty ? .info : .review)
        }
        if limited {
            add(&e, "Application integrity", "Application scan limit",
                "The scan stopped after \(maximumApplications) application bundles. Additional applications were not checked.", .review)
        }
        if !inaccessibleRoots.isEmpty {
            add(&e, "Application integrity", "Application scan coverage",
                "Application directories could not be enumerated: \(inaccessibleRoots.joined(separator: ", "))", .review)
        }
    }

    private func scanStartupFiles(into e: inout [Evidence]) {
        let fm = FileManager.default
        let home = fm.homeDirectoryForCurrentUser
        let roots = [
            URL(fileURLWithPath: "/Library/LaunchAgents"), URL(fileURLWithPath: "/Library/LaunchDaemons"),
            home.appendingPathComponent("Library/LaunchAgents"),
            URL(fileURLWithPath: "/Library/StartupItems"), URL(fileURLWithPath: "/System/Library/StartupItems"),
            home.appendingPathComponent("Library/Application Support/Microsoft/Office/Startup"),
            home.appendingPathComponent("Library/Group Containers/UBF8T346G9.Office/User Content/Startup")
        ]
        var rows: [String] = []
        var inaccessibleRoots: [String] = []
        var limitedRoots: [String] = []
        var reachedRowLimit = false
        for root in roots {
            guard fm.fileExists(atPath: root.path) else { continue }
            guard let files = try? fm.contentsOfDirectory(at: root, includingPropertiesForKeys: [.isRegularFileKey, .contentModificationDateKey], options: [.skipsHiddenFiles]) else {
                inaccessibleRoots.append(root.path)
                continue
            }
            if files.count > 250 { limitedRoots.append(root.path) }
            for file in files.prefix(250) {
                let name = file.lastPathComponent.lowercased()
                let isMacroPath = root.path.localizedCaseInsensitiveContains("Office")
                if isMacroPath || file.pathExtension == "plist" {
                    let values = try? file.resourceValues(forKeys: [.contentModificationDateKey, .isRegularFileKey])
                    rows.append("\(file.path) | modified \(values?.contentModificationDate?.description ?? "unknown")" + (isMacroPath ? " | Office startup location: review macros/add-ins" : ""))
                    if rows.count >= 500 { break }
                }
                if ["update", "helper", "agent", "support", "sync", "monitor", "remote"].contains(where: name.contains) {
                    rows.append("Name heuristic: \(file.path)")
                }
                if rows.count >= 500 {
                    reachedRowLimit = true
                    break
                }
            }
            if reachedRowLimit { break }
        }
        var detail = rows.joined(separator: "\n")
        if !inaccessibleRoots.isEmpty {
            detail += "\nDirectories that could not be read: \(inaccessibleRoots.joined(separator: ", "))"
        }
        if !limitedRoots.isEmpty {
            detail += "\nDirectories capped at 250 entries: \(limitedRoots.joined(separator: ", "))"
        }
        if reachedRowLimit { detail += "\nEvidence display stopped after 500 entries." }
        let isPartial = !inaccessibleRoots.isEmpty || !limitedRoots.isEmpty || reachedRowLimit
        let level: Evidence.Level = rows.isEmpty && !isPartial ? .info : .review
        add(&e, "Persistence", "Launch agents, daemons, and Office startup files", detail, level)
    }
}

@main
@MainActor
struct MacSentinelApp: App {
    @StateObject private var model = AuditModel()
    @StateObject private var updater = UpdateModel()
    init() { configureLogging() }
    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(model)
                .environmentObject(updater)
                .frame(minWidth: 760, minHeight: 620)
        }.windowResizability(.contentSize)
    }
}

@MainActor
struct ContentView: View {
    @EnvironmentObject private var model: AuditModel
    @EnvironmentObject private var updater: UpdateModel

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 24) {
                header
                if updater.status != .idle {
                    updateBanner
                }

                if model.running {
                    scanningState
                } else if model.evidence.isEmpty {
                    emptyState
                } else {
                    dashboard
                }
            }
            .frame(maxWidth: 1180, alignment: .leading)
            .padding(24)
            .frame(maxWidth: .infinity, alignment: .top)
        }
        .background(Color(nsColor: .windowBackgroundColor))
        .alert("Could not export report", isPresented: Binding(
            get: { model.error != nil },
            set: { if !$0 { model.error = nil } }
        )) {
            Button("OK", role: .cancel) { model.error = nil }
        } message: {
            Text(model.error ?? "")
        }
        .task {
            updater.startAutomaticChecks()
        }
    }

    private var header: some View {
        HStack(spacing: 16) {
            Image(systemName: "checkmark.shield.fill")
                .font(.system(size: 28, weight: .medium))
                .foregroundStyle(Color.accentColor)
                .frame(width: 52, height: 52)
                .background(Color.accentColor.opacity(0.10), in: RoundedRectangle(cornerRadius: 14))
                .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: 4) {
                Text("MacSentinel")
                    .font(.title2.weight(.semibold))
                Text("Read-only security evidence")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }

            Spacer(minLength: 16)

            Button(action: model.run) {
                Label(model.running ? "Scanning…" : "Run scan", systemImage: "arrow.clockwise")
            }
            .buttonStyle(.borderedProminent)
            .disabled(model.running)
            .keyboardShortcut("r", modifiers: [.command])

            Button(action: updater.checkManually) {
                Label(updater.buttonTitle, systemImage: "arrow.down.circle")
            }
            .buttonStyle(.bordered)
            .disabled(updater.isBusy)
            .help("Check GitHub Releases and download a newer MacSentinel DMG")

            Button(action: model.export) {
                Label("Export", systemImage: "square.and.arrow.up")
            }
            .buttonStyle(.bordered)
            .disabled(model.evidence.isEmpty || model.running)
        }
    }

    private var updateBanner: some View {
        let copy = updateStatusCopy
        return HStack(alignment: .top, spacing: 12) {
            Image(systemName: copy.symbol)
                .foregroundStyle(copy.tint)
                .frame(width: 20)
                .padding(.top, 2)
                .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: 4) {
                Text(copy.title)
                    .font(.subheadline.weight(.semibold))
                Text(copy.detail)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
            }

            Spacer(minLength: 8)

            if case let .downloaded(_, url) = updater.status {
                Button("Open DMG") {
                    updater.openDownloadedDMG(at: url)
                }
                .buttonStyle(.bordered)
            } else if case .failed = updater.status {
                Button("Retry") {
                    updater.checkManually()
                }
                .buttonStyle(.bordered)
                .disabled(updater.isBusy)
            }

            if !updater.isBusy {
                Button {
                    updater.dismissStatus()
                } label: {
                    Image(systemName: "xmark")
                }
                .buttonStyle(.borderless)
                .accessibilityLabel("Dismiss update status")
            }
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.background, in: RoundedRectangle(cornerRadius: 12))
        .overlay {
            RoundedRectangle(cornerRadius: 12)
                .strokeBorder(copy.tint.opacity(0.18), lineWidth: 1)
        }
    }

    private var updateStatusCopy: (symbol: String, title: String, detail: String, tint: Color) {
        switch updater.status {
        case .idle:
            ("arrow.down.circle", "Updates", "No update check has run yet.", .secondary)
        case .checking:
            ("arrow.triangle.2.circlepath", "Checking for updates", "Checking the latest MacSentinel release on GitHub.", .secondary)
        case let .downloading(version):
            ("arrow.down.circle", "Downloading MacSentinel \(version)", "The DMG is being downloaded and its GitHub-published SHA-256 digest will be verified.", .accentColor)
        case let .upToDate(version):
            ("checkmark.circle", "MacSentinel is up to date", "Running version \(version); no newer GitHub release was found.", .secondary)
        case let .downloaded(version, url):
            ("checkmark.seal", "MacSentinel \(version) is ready", "Saved as \(url.lastPathComponent) in Downloads. This community build is not notarized and may prompt Gatekeeper; proceed only if you trust the source. Open the DMG, quit MacSentinel, then drag the app to Applications to replace it.", .green)
        case let .failed(message):
            ("exclamationmark.triangle", "Update check failed", "\(message) Your current app was not changed.", .orange)
        }
    }

    private var emptyState: some View {
        ContentUnavailableView {
            Label("Your security snapshot starts here", systemImage: "shield.lefthalf.filled")
        } description: {
            Text("Run a local, read-only scan to collect system, network, persistence, and application-signature evidence.")
        } actions: {
            Button(action: model.run) {
                Label("Run first scan", systemImage: "viewfinder")
            }
            .buttonStyle(.borderedProminent)
        }
        .frame(maxWidth: .infinity, minHeight: 420)
        .background(.background, in: RoundedRectangle(cornerRadius: 18))
        .overlay(alignment: .bottom) {
            Text("MacSentinel gathers evidence; it does not determine that a Mac is clean.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .padding(.bottom, 20)
        }
    }

    private var scanningState: some View {
        VStack(alignment: .leading, spacing: 20) {
            HStack(spacing: 14) {
                ProgressView()
                    .controlSize(.large)
                VStack(alignment: .leading, spacing: 4) {
                    Text("Collecting security evidence")
                        .font(.title3.weight(.semibold))
                    Text("Checks run locally. Some system data may be unavailable without additional permissions.")
                        .foregroundStyle(.secondary)
                }
            }
            .padding(22)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(.background, in: RoundedRectangle(cornerRadius: 16))

            if !model.evidence.isEmpty {
                dashboard
                    .opacity(0.55)
                    .allowsHitTesting(false)
                    .accessibilityHidden(true)
            }
        }
    }

    private var dashboard: some View {
        VStack(alignment: .leading, spacing: 18) {
            snapshotBanner
            summaryMetrics

            LazyVGrid(columns: [GridItem(.adaptive(minimum: 320), spacing: 16)], alignment: .leading, spacing: 16) {
                categoryPanel
                reviewPanel
            }

            evidencePanel
            limitationsNote
        }
    }

    private var snapshotBanner: some View {
        HStack(alignment: .top, spacing: 14) {
            Image(systemName: model.concernCount > 0 ? "exclamationmark.triangle.fill" : "doc.text.magnifyingglass")
                .font(.title2)
                .foregroundStyle(model.concernCount > 0 ? Color.red : Color.accentColor)
                .frame(width: 42, height: 42)
                .background(
                    (model.concernCount > 0 ? Color.red : Color.accentColor).opacity(0.10),
                    in: RoundedRectangle(cornerRadius: 12)
                )
                .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: 5) {
                Text(snapshotTitle)
                    .font(.title3.weight(.semibold))
                Text(snapshotDescription)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                if let lastRun = model.lastRun {
                    Label {
                        Text("Scanned \(lastRun.formatted(date: .abbreviated, time: .shortened)) · \(Host.current().localizedName ?? "This Mac")")
                    } icon: {
                        Image(systemName: "clock")
                    }
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .padding(.top, 2)
                }
            }
            Spacer(minLength: 0)
        }
        .padding(20)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.background, in: RoundedRectangle(cornerRadius: 16))
        .overlay {
            RoundedRectangle(cornerRadius: 16)
                .strokeBorder(Color.primary.opacity(0.07), lineWidth: 1)
        }
    }

    private var snapshotTitle: String {
        if model.concernCount > 0 { return "\(model.concernCount) item\(model.concernCount == 1 ? "" : "s") marked for attention" }
        if model.reviewCount > 0 { return "\(model.reviewCount) item\(model.reviewCount == 1 ? "" : "s") need review" }
        return "Evidence collected"
    }

    private var snapshotDescription: String {
        if model.reviewCount > 0 {
            return "These results need context; a review flag is not a malware verdict."
        }
        return "No review flags in the evidence collected. This is not a clean bill of health."
    }

    private var summaryMetrics: some View {
        LazyVGrid(columns: [GridItem(.adaptive(minimum: 180), spacing: 12)], alignment: .leading, spacing: 12) {
            MetricTile(
                title: "Needs review",
                value: "\(model.reviewCount)",
                detail: "Evidence items",
                symbol: "magnifyingglass",
                tint: model.reviewCount > 0 ? .orange : .secondary
            )
            MetricTile(
                title: "Collected",
                value: "\(model.evidence.count)",
                detail: "Evidence items",
                symbol: "doc.text",
                tint: .blue
            )
            MetricTile(
                title: "Categories",
                value: "\(model.categories.count)",
                detail: "Areas inspected",
                symbol: "square.grid.2x2",
                tint: .teal
            )
        }
    }

    private var categoryPanel: some View {
        VStack(alignment: .leading, spacing: 16) {
            panelHeading("Evidence by category", subtitle: "Select a category to filter results.")

            if model.categories.isEmpty {
                Text("No category data was returned.")
                    .foregroundStyle(.secondary)
            } else {
                Chart(model.categories) { category in
                    BarMark(
                        x: .value("Evidence items", category.count),
                        y: .value("Category", category.name),
                        height: 16
                    )
                    .foregroundStyle(category.reviewCount > 0 ? Color.orange.gradient : Color.accentColor.gradient)
                    .cornerRadius(5)
                }
                .chartLegend(.hidden)
                .chartXAxis {
                    AxisMarks(position: .bottom, values: .automatic(desiredCount: 4)) { value in
                        AxisGridLine()
                        AxisValueLabel()
                    }
                }
                .chartYAxis {
                    AxisMarks(position: .leading) { _ in
                        AxisValueLabel()
                    }
                }
                .frame(height: max(150, CGFloat(model.categories.count) * 32))
                .accessibilityLabel("Evidence items grouped by category")

                Divider()

                HStack {
                    Picker("Filter evidence", selection: $model.selectedCategory) {
                        Text("All categories").tag(String?.none)
                        ForEach(model.categories) { category in
                            Text(category.name).tag(Optional(category.name))
                        }
                    }
                    .pickerStyle(.menu)
                    .labelsHidden()
                    .accessibilityLabel("Filter evidence by category")

                    Spacer()

                    Text("\(model.evidence.count) total")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
        }
        .panelStyle()
    }

    private var reviewPanel: some View {
        VStack(alignment: .leading, spacing: 14) {
            panelHeading(
                "Review & response",
                subtitle: model.reviewCount == 0
                    ? "No items are currently marked for review."
                    : "Evidence-linked next steps. MacSentinel never changes settings for you."
            )

            if model.reviewEvidence.isEmpty {
                Label("No review flags in this snapshot", systemImage: "checkmark.circle")
                    .foregroundStyle(.secondary)
                    .padding(.vertical, 8)
            } else {
                ForEach(Array(model.reviewEvidence.prefix(4))) { item in
                    Button {
                        model.selectedCategory = item.category
                    } label: {
                        HStack(alignment: .top, spacing: 10) {
                            Image(systemName: item.level == .concern ? "exclamationmark.triangle.fill" : "magnifyingglass")
                                .foregroundStyle(item.level == .concern ? Color.red : Color.orange)
                                .frame(width: 18)
                                .padding(.top, 2)
                            VStack(alignment: .leading, spacing: 3) {
                                Text(item.title)
                                    .font(.subheadline.weight(.medium))
                                    .multilineTextAlignment(.leading)
                                    .foregroundStyle(.primary)
                                Text(item.guidance?.summary ?? item.category)
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                                    .lineLimit(2)
                                if let firstStep = item.guidance?.steps.first {
                                    Text(firstStep)
                                        .font(.caption2)
                                        .foregroundStyle(.secondary)
                                        .lineLimit(2)
                                }
                            }
                            Spacer(minLength: 0)
                            Image(systemName: "chevron.right")
                                .font(.caption.weight(.semibold))
                                .foregroundStyle(.tertiary)
                        }
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                    .accessibilityHint("Filters the evidence list to \(item.category).")
                }

                if model.reviewCount > 4 {
                    Text("+ \(model.reviewCount - 4) more items in the full evidence list")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .padding(.top, 2)
                }
            }
        }
        .panelStyle()
    }

    private var evidencePanel: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(alignment: .center) {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Collected evidence")
                        .font(.headline)
                    Text(model.selectedCategory ?? "Inspect individual results and command output.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }

                Spacer()

                if model.selectedCategory != nil {
                    Button("Clear filter") { model.selectedCategory = nil }
                        .buttonStyle(.borderless)
                }

                Text("\(model.visibleEvidence.count)")
                    .font(.caption.monospacedDigit())
                    .foregroundStyle(.secondary)
            }

            Divider()

            LazyVStack(alignment: .leading, spacing: 0) {
                ForEach(Array(model.visibleEvidence.enumerated()), id: \.element.id) { index, item in
                    EvidenceRow(item: item)
                    if index < model.visibleEvidence.count - 1 {
                        Divider().padding(.leading, 32)
                    }
                }
            }
        }
        .panelStyle()
    }

    private var limitationsNote: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label("Read this snapshot in context", systemImage: "info.circle")
                .font(.subheadline.weight(.semibold))
            Text("MacSentinel is a read-only triage tool, not antivirus software. Protected data may be unavailable, and a valid application signature does not establish that software is safe.")
                .font(.caption)
                .foregroundStyle(.secondary)
            Text("Unexpected names, paths, permissions, and connections are leads to investigate—not findings of malicious activity.")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .padding(.horizontal, 4)
    }

    private func panelHeading(_ title: String, subtitle: String) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title)
                .font(.headline)
            Text(subtitle)
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }
}

private struct MetricTile: View {
    let title: String
    let value: String
    let detail: String
    let symbol: String
    let tint: Color

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: symbol)
                .font(.system(size: 16, weight: .semibold))
                .foregroundStyle(tint)
                .frame(width: 36, height: 36)
                .background(tint.opacity(0.10), in: RoundedRectangle(cornerRadius: 10))
                .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                HStack(alignment: .firstTextBaseline, spacing: 5) {
                    Text(value)
                        .font(.title2.weight(.semibold).monospacedDigit())
                    Text(detail)
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }
            }
            Spacer(minLength: 0)
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.background, in: RoundedRectangle(cornerRadius: 14))
        .overlay {
            RoundedRectangle(cornerRadius: 14)
                .strokeBorder(Color.primary.opacity(0.07), lineWidth: 1)
        }
        .accessibilityElement(children: .combine)
    }
}

private struct EvidenceRow: View {
    let item: Evidence

    private var symbol: String {
        switch item.level {
        case .info: "checkmark.circle"
        case .review: "magnifyingglass"
        case .concern: "exclamationmark.triangle.fill"
        }
    }

    private var tint: Color {
        switch item.level {
        case .info: .secondary
        case .review: .orange
        case .concern: .red
        }
    }

    var body: some View {
        DisclosureGroup {
            if let guidance = item.guidance {
                VStack(alignment: .leading, spacing: 8) {
                    Label("Suggested next steps", systemImage: "lightbulb")
                        .font(.subheadline.weight(.semibold))
                    Text(guidance.summary)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    ForEach(Array(guidance.steps.enumerated()), id: \.offset) { index, step in
                        HStack(alignment: .top, spacing: 8) {
                            Text("\(index + 1).")
                                .font(.caption.monospacedDigit().weight(.semibold))
                                .foregroundStyle(.secondary)
                            Text(step)
                                .font(.caption)
                                .textSelection(.enabled)
                        }
                    }
                }
                .padding(12)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Color.accentColor.opacity(0.06), in: RoundedRectangle(cornerRadius: 10))
                .padding(.vertical, 8)
            }

            Text(item.detail)
                .font(.system(.caption, design: .monospaced))
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.vertical, 8)
        } label: {
            HStack(alignment: .center, spacing: 10) {
                Image(systemName: symbol)
                    .foregroundStyle(tint)
                    .frame(width: 20)
                    .accessibilityHidden(true)

                VStack(alignment: .leading, spacing: 3) {
                    Text(item.title)
                        .font(.subheadline.weight(.medium))
                        .foregroundStyle(.primary)
                    Text(item.category)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }

                Spacer()

                Text(item.level.label)
                    .font(.caption)
                    .foregroundStyle(tint)
            }
            .padding(.vertical, 9)
            .contentShape(Rectangle())
        }
        .accessibilityHint("Shows the collected command output and details.")
    }
}

private extension Evidence.Level {
    var sortOrder: Int {
        switch self {
        case .info: 0
        case .review: 1
        case .concern: 2
        }
    }

    var label: String {
        switch self {
        case .info: "Collected"
        case .review: "Review"
        case .concern: "Attention"
        }
    }
}

private extension View {
    func panelStyle() -> some View {
        padding(18)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(.background, in: RoundedRectangle(cornerRadius: 16))
            .overlay {
                RoundedRectangle(cornerRadius: 16)
                    .strokeBorder(Color.primary.opacity(0.07), lineWidth: 1)
            }
    }
}
