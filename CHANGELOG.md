# Changelog

## 0.1.0 — local candidate notes

These are local release notes for the untagged, unpublished `0.1.0` candidate.
They do not announce a GitHub Release, npm publication, or production rollout.

### Added

- A mock-first security incident triage workflow with approval-gated mock
  containment.
- Retention scheduling for one explicitly configured tenant every 24 hours,
  plus a tenant-scoped manual dry-run command.
- Local SQLite retention audit/claim migrations and Apache-2.0 community
  template metadata.

### Operational notes

- Real WorkOS, IPinfo, Linear, and Upstash integrations remain staging opt-ins
  and fail early when configuration is incomplete.
- GeoIP and device signals are evidence for correlation, not standalone proof.
