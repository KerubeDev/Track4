# Issue Tracker

## Tracker

GitHub Issues in `KerubeDev/Track4` are the issue tracker for this repo.

## Workflow

- Create and update issues with `gh issue`.
- Publish linked work items in issue order when a skill expects tracker-backed handoff.
- Use `gh pr` for PR publication and review metadata when a skill hands off to code review or shipment.

## Defaults

- Default tracker labels for spec publication: `spec`, `ready-for-agent`.
- Default tracker labels for tickets: `ready-for-agent` plus any justified area or priority labels inherited from the source spec.
- Keep milestones, project items, and fields aligned with the canonical work-item format.
- Sub-issue relationships are created with `gh issue create --parent <N>` (main issue → specs → tickets).
- Blocking edges between tickets are declared textually in each ticket body under `Blocked by:` (the REST links endpoint is not available in this repo).
- Milestones in use: `Track4 - Sprint` (implementation) and `Track4 - Delivery` (repo + video, due 2026-09-11).

## Wayfinding operations

- `to-spec` publishes one spec issue.
- `to-tickets` publishes tracer-bullet tickets with explicit blockers.
- `publish-open-pr` publishes a prepared branch as a PR.
- `ship-subissue` merges a clean subissue PR and closes the linked issue when needed.

## Notes

- PRs are not treated as a general request surface unless a skill explicitly says so.
- The execution tree lives in the repo's issues: `#2` (Epic context) → `#3`/`#4` (specs) → tickets under each spec.
