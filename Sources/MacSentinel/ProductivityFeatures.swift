import Foundation

enum ScanProfile: String, CaseIterable, Codable, Identifiable, Sendable {
    case quick
    case full

    var id: String { rawValue }

    var title: String {
        switch self {
        case .quick: "Quick check"
        case .full: "Full scan"
        }
    }

    var description: String {
        switch self {
        case .quick: "Core protections, network exposure, and persistence."
        case .full: "All checks, including application signatures and recent security logs."
        }
    }
}

enum ScanSchedule: String, CaseIterable, Identifiable, Sendable {
    case off
    case daily
    case weekly

    var id: String { rawValue }

    var title: String {
        switch self {
        case .off: "Off"
        case .daily: "Daily"
        case .weekly: "Weekly"
        }
    }

    var interval: TimeInterval? {
        switch self {
        case .off: nil
        case .daily: 86_400
        case .weekly: 604_800
        }
    }
}

struct ScanSnapshot: Identifiable, Codable, Sendable {
    let id: UUID
    let generatedAt: Date
    let profile: ScanProfile
    let evidence: [Evidence]

    init(id: UUID = UUID(), generatedAt: Date, profile: ScanProfile, evidence: [Evidence]) {
        self.id = id
        self.generatedAt = generatedAt
        self.profile = profile
        self.evidence = evidence
    }

    var reviewCount: Int {
        evidence.filter { $0.level != .info }.count
    }

    var concernCount: Int {
        evidence.filter { $0.level == .concern }.count
    }
}

struct ScanDiff: Sendable {
    let previousDate: Date
    let added: [Evidence]
    let resolved: [Evidence]
    let changed: [Evidence]

    init?(previous: ScanSnapshot?, current: ScanSnapshot) {
        guard let previous, previous.profile == current.profile else { return nil }
        previousDate = previous.generatedAt

        let oldReview = previous.evidence.reduce(into: [String: Evidence]()) { result, item in
            if item.level != .info { result["\(item.category)|\(item.title)"] = item }
        }
        let newReview = current.evidence.reduce(into: [String: Evidence]()) { result, item in
            if item.level != .info { result["\(item.category)|\(item.title)"] = item }
        }

        let addedItems = newReview.compactMap { entry -> Evidence? in
            let (key, item) = entry
            return oldReview[key] == nil ? item : nil
        }
        let resolvedItems = oldReview.compactMap { entry -> Evidence? in
            let (key, item) = entry
            return newReview[key] == nil ? item : nil
        }
        let changedItems = newReview.compactMap { entry -> Evidence? in
            let (key, item) = entry
            guard let old = oldReview[key],
                  old.level != item.level || old.detail != item.detail else { return nil }
            return item
        }
        added = addedItems.sorted { $0.title.localizedCaseInsensitiveCompare($1.title) == .orderedAscending }
        resolved = resolvedItems.sorted { $0.title.localizedCaseInsensitiveCompare($1.title) == .orderedAscending }
        changed = changedItems.sorted { $0.title.localizedCaseInsensitiveCompare($1.title) == .orderedAscending }
    }
}

struct ScanHistoryStore {
    private let fileManager = FileManager.default

    private var historyURL: URL {
        let support = fileManager.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? fileManager.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support", isDirectory: true)
        return support
            .appendingPathComponent("MacSentinel", isDirectory: true)
            .appendingPathComponent("scan-history.json")
    }

    func load() throws -> [ScanSnapshot] {
        guard fileManager.fileExists(atPath: historyURL.path) else { return [] }
        let data = try Data(contentsOf: historyURL)
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try decoder.decode([ScanSnapshot].self, from: data)
            .sorted { $0.generatedAt > $1.generatedAt }
    }

    func save(_ snapshots: [ScanSnapshot]) throws {
        let directory = historyURL.deletingLastPathComponent()
        try fileManager.createDirectory(at: directory, withIntermediateDirectories: true)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        try encoder.encode(snapshots).write(to: historyURL, options: .atomic)
    }
}

struct RedactedAuditReport: Encodable {
    struct Item: Encodable {
        let category: String
        let status: Evidence.Level
        let explanation: String?
        let suggestedSteps: [String]
    }

    let generatedAt: Date
    let macOS: String
    let profile: ScanProfile
    let reviewCount: Int
    let attentionCount: Int
    let evidence: [Item]

    init(snapshot: ScanSnapshot, macOS: String) {
        generatedAt = snapshot.generatedAt
        self.macOS = macOS
        profile = snapshot.profile
        reviewCount = snapshot.reviewCount
        attentionCount = snapshot.concernCount
        evidence = snapshot.evidence.map {
            Item(
                category: $0.category,
                status: $0.level,
                explanation: $0.guidance?.summary,
                suggestedSteps: $0.guidance?.steps ?? []
            )
        }
    }
}

extension ScanGuidance {
    var estimatedEffort: String {
        if steps.contains(where: {
            $0.localizedCaseInsensitiveContains("recovery")
                || $0.localizedCaseInsensitiveContains("terminal")
                || $0.localizedCaseInsensitiveContains("restart")
        }) {
            return "Advanced"
        }
        return steps.count > 1 ? "Guided" : "Quick"
    }
}
