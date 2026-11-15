# Beacon security audit

The final FF3 audit completed on **2026-11-15** (America/St_Johns), against commit `cff28dd31c5620390d6218cfa6448da0f5d07872`. It was a **full audit, all phases, standard profile**, with a complete run status, a passing final clean critic and **zero open findings**. No parked or follow-up items remained in the final FF3 findings record.

## Method and provenance

Independent lane reviewers used [cloudflare/security-audit-skill](https://github.com/cloudflare/security-audit-skill), vendored at commit `c1c8a8c1471069fb0e188eeaff69b8e8db6564a8` under the MIT license. The result describes the use of that open-source method by the independent reviewers. It does not imply that the skill's publisher performed or endorsed this audit.

The full run covered the repository source and its then-current README, documentation and static site. Compatible prior coverage was carried forward with its evidence; changed source received fresh review. All six phases were represented:

1. Reconnaissance mapped architecture, trust boundaries and coverage units.
2. Coverage-led hunting reviewed application boundaries, administration and migrations, HTTP and WebSockets, and documentation. Critics checked coverage gaps.
3. Candidate validation rechecked prior findings against the current source; no new source-grounded candidate remained.
4. Structured output recorded an empty current findings array and validated the findings and coverage records.
5. Independent record verification reviewed final claims; stale invocation/report state was corrected before a separate final clean critic passed.
6. Target-neutral reporting assembled the final report, finding details and validation dispositions from those records.

The retained lane package contains the reconnaissance, hunting, architecture, empty `findings.json`, record-verification, `REPORT.md` and complete `run-metadata.json` artifacts. The final audit report records that the unmodified findings and coverage validators and their self-tests passed. These internal artifacts are not published in this repository; this document is their public summary.

## How the result changed across runs

| Run | Result and subsequent work |
| --- | --- |
| Original 2026-11-14 run | **Incomplete.** The final-clean critic reopened coverage, so this run is not a complete PASS. Confirmed items included login-bucket isolation, UDP worker removal while holding the map lock, and generated TLS private-file permissions. Fixes were committed forward; other candidates required later validation. |
| FF1 | Further forward fixes addressed route withdrawal and cancellation races, restricted administrative binds, updated dependencies and tightened authentication and certificate handling. Later reviews independently reassessed prior candidates, rejecting unsupported security claims rather than presenting every candidate as a confirmed defect. |
| FF2 | No confirmed open findings. Login lockout and unbounded WebSocket handshake wait were closed with regressions that failed on pre-fix source and passed after the fix. Deployment-policy, legacy-row compatibility and offline dependency-index follow-ups remained parked; this was not the final clean result. |
| FF3 | **Complete standard-profile PASS at the commit above.** Explicit trusted-proxy handling isolated login budgets and rebuilt forwarded identity by default. Optional WebSocket Origin checks run before upstream contact. Unsupported legacy aliases fail startup closed. Documentation closes the offline-index follow-up by explicitly disclosing the limitation and giving maintainer checks. All FF3 items were closed, with zero open, parked or follow-up items. |

## Recorded verification

The FF3 matrix recorded **199 passed, 0 failed**, including **45 database test executions**. Required groups included formatting, Clippy with warnings denied, default and `game_forward` builds and workspace tests, dedicated PostgreSQL tests and Node user-interface assertions. Capture regeneration reproduced the committed terminal images. Worktree, new-patch and output scans reported effective 0/0/0.

Offline `cargo audit` returned zero vulnerability records using RustSec advisory database commit `4ef2df8e806a65e2f1ecc14f56f51249062b23d6`. `cargo deny` passed the default and `game_forward` dependency graphs with no ignore rules.

## Scope and limits

This is a repository review, not a live-deployment assessment or a guarantee that software has no vulnerabilities. No live host, upstream or external service was contacted. Operators must configure trusted proxies, encrypted management ingress and WebSocket Origin enforcement for their deployment.

The staged advisory snapshot lacked crates.io index records, so **yanked package status was not checked**. The zero-vulnerability result does not establish that all locked packages are unyanked. See [dependency checks](docs/SECURITY.md) for network-enabled maintainer commands.

This FF4 update changes documentation and local assets only. It preserves the exact FF3 audited commit above and removes the separate Pages site in favor of the repository README. The badges refer to that FF3 evidence, rather than a fresh build or a live service.
