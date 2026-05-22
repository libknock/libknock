# validation-update recipe

## Applicable scenario

Release-candidate documentation work that updates validation evidence, platform support, known limitations, release notes, or changelog entries without changing runtime code.

## Files to modify

- CHANGELOG.md
- docs/release-notes.md
- docs/release-notes/*.md
- docs/validation/*.md
- docs/validation-matrix.md
- docs/platform-support.md
- docs/known-limitations.md
- docs/release-checklist.md
- docs/llms.md and llms.txt when agent-facing release guidance changes

## Files not to modify

- protocol/, auth/, firewall/, gate/, relay/, knock/, internal/ unless the task explicitly includes code changes.
- Do not rewrite historical validation records except to fix broken links or obvious typos.

## Minimal shape

```text
state what was run, what was not run, reason, risk, and follow-up; keep release claims no stronger than the evidence
```

## Common mistakes

- Treating unit tests, dry-run firewall scripts, or loopback integration as real-host firewall validation.
- Claiming Windows/macOS packet paths are runtime-validated without attached host evidence.
- Omitting the standard versus with-vendor artifact distinction.
- Adding a changelog entry without linking the detailed release note.

## Validation commands

```sh
python3 scripts/check-doc-links.py
git diff --check
```

Run broader release gates only when the change affects code, scripts, module metadata, or archive packaging.
