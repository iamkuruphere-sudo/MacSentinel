import SwiftUI
import AppKit
import Darwin
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
    enum Level: String, Codable, Sendable { case info, review, concern }
}

struct AuditReport: Codable {
    let generatedAt: Date
    let host: String
    let macOS: String
    let evidence: [Evidence]
    let limitations: [String]
}

@MainActor
final class AuditModel: ObservableObject {
    @Published var running = false
    @Published var evidence: [Evidence] = []
    @Published var lastRun: Date?
    @Published var error: String?

    func run() {
        guard !running else { return }
        running = true
        error = nil
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
        out.append(Evidence(category: category, title: title, detail: shown + clipped, level: level))
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
    init() { configureLogging() }
    var body: some Scene {
        WindowGroup {
            ContentView().environmentObject(model).frame(minWidth: 760, minHeight: 620)
        }.windowResizability(.contentSize)
    }
}

struct ContentView: View {
    @EnvironmentObject private var model: AuditModel
    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            HStack(alignment: .top) {
                VStack(alignment: .leading, spacing: 5) {
                    Text("MacSentinel").font(.largeTitle.bold())
                    Text("Read-only endpoint evidence review").foregroundStyle(.secondary)
                }
                Spacer()
                Button { model.run() } label: {
                    Label(model.running ? "Scanning…" : "Run scan", systemImage: "viewfinder")
                }.buttonStyle(.borderedProminent).disabled(model.running)
                Button { model.export() } label: { Label("Export report", systemImage: "square.and.arrow.up") }
                    .disabled(model.evidence.isEmpty)
            }
            if let lastRun = model.lastRun { Text("Last scan: \(lastRun.formatted(date: .abbreviated, time: .shortened))") .font(.caption).foregroundStyle(.secondary) }
            HStack(spacing: 10) {
                Label("Detection leads need review", systemImage: "checkmark.shield").font(.headline)
                Spacer()
                Text("Settings and files under review are not altered").font(.caption).foregroundStyle(.secondary)
            }.padding(14).background(.blue.opacity(0.08), in: RoundedRectangle(cornerRadius: 12))
            Text("Checks persistence, Office startup locations, update history, network listeners, profiles, extensions, core security settings, and recent Unified Logs. A scan cannot prove a device is clean or validate firmware from user space.")
                .font(.callout).foregroundStyle(.secondary)
            if let error = model.error { Text(error).foregroundStyle(.red) }
            if model.evidence.isEmpty && !model.running {
                ContentUnavailableView("No scan yet", systemImage: "desktopcomputer.trianglebadge.exclamationmark", description: Text("Run a scan to collect a point-in-time evidence snapshot."))
                Spacer()
            } else {
                List {
                    ForEach(model.evidence) { item in
                        DisclosureGroup {
                            Text(item.detail).font(.system(.caption, design: .monospaced)).textSelection(.enabled).padding(.vertical, 5)
                        } label: {
                            HStack {
                                Image(systemName: item.level == .concern ? "exclamationmark.triangle.fill" : item.level == .review ? "magnifyingglass" : "checkmark.circle")
                                    .foregroundStyle(item.level == .concern ? .red : item.level == .review ? .orange : .secondary)
                                VStack(alignment: .leading) {
                                    Text(item.title).fontWeight(.medium)
                                    Text(item.category).font(.caption).foregroundStyle(.secondary)
                                }
                            }
                        }
                    }
                }.listStyle(.inset)
            }
            Text("Some checks may be partial without administrator access or Full Disk Access. Review unexpected names, paths, publishers, and dates before drawing conclusions.")
                .font(.caption2).foregroundStyle(.secondary)
        }.padding(22)
    }
}
