# spike/core-engine-split — ISOLATED, NEVER MERGE

Proof-of-tractability for the Core Engine/UI split (`VAL-P0-CORE-014`). This package is **not** part of
the product build and **must never be merged to `main`**. It exists only on the `spike/core-engine-split`
branch as evidence that a UI-free `OpenBurnBarEngine` target can be carved from `OpenBurnBarCore` and
compiled on macOS.

## What this is
- `Package.swift` — a standalone SwiftPM package with **zero** Vendor / xcframework / remote-package
  dependencies.
- `Sources/OpenBurnBarEngine/` — real production model files carved from
  `OpenBurnBarCore/Sources/OpenBurnBarCore/SharedModels` (seeded by the 32-case `AgentProvider`, whose
  vestigial `import SwiftUI` is deleted — it uses no SwiftUI symbols).
- `Sources/OpenBurnBarFirestoreModels/` — a copy of the pre-existing Foundation-only leaf target that
  production Core already depends on.
- `evidence/macos-compile.log` — the captured `swift build` output.

## Reproduce
```bash
rm -rf .build && swift build          # → Build complete!
grep -rh '^import' Sources | sort | uniq -c   # → only "import Foundation"
```

## Why it matters
Production `OpenBurnBarCore` is untouched (`git diff --stat main -- OpenBurnBarCore/` is empty on this
branch). The full analysis + untangle plan lives in
[`docs/windows-port/CORE_ENGINE_SPLIT_FEASIBILITY.md`](../../docs/windows-port/CORE_ENGINE_SPLIT_FEASIBILITY.md).
