// swift-tools-version: 6.0
// SPDX-License-Identifier: AGPL-3.0-only
//
// ISOLATED SPIKE — NEVER MERGED. Proof-of-tractability for the Core Engine/UI
// split (VAL-P0-CORE-014). Carves a UI-free `OpenBurnBarEngine` target seeded
// from the 32-case `AgentProvider` + the Foundation-only SharedModels closure,
// plus the pre-existing Foundation-only `OpenBurnBarFirestoreModels` leaf (which
// production Core already depends on). Production `OpenBurnBarCore` is untouched;
// ZERO Vendor / SwiftUI / AppKit / UIKit deps; builds standalone via `swift build`.
import PackageDescription

let package = Package(
    name: "OpenBurnBarEngine",
    platforms: [.macOS(.v14), .iOS(.v17)],
    products: [
        .library(name: "OpenBurnBarEngine", targets: ["OpenBurnBarEngine"])
    ],
    targets: [
        .target(
            name: "OpenBurnBarFirestoreModels",
            path: "Sources/OpenBurnBarFirestoreModels"
        ),
        .target(
            name: "OpenBurnBarEngine",
            dependencies: ["OpenBurnBarFirestoreModels"],
            path: "Sources/OpenBurnBarEngine"
        )
    ],
    swiftLanguageModes: [.v6]
)
