# Submission Dry-Run Checklist

Built per partner's task list item 4, morning of 23/09 (freeze 15:00, submit
23:00, deadline 23:59 per `progress.md`/`CLAUDE.md`).

## Repository

- URL: https://github.com/FediJlassi/sentinel-shield
- Final commit hash: **TODO** — fill in at the 23:00 submission step, after
  the `partner/redaction-fix` merge and any last-minute fixes land on `main`.
  Do not fill this in early; a hash recorded now will be stale by freeze.

## Video

- Filename: **TODO** — not yet decided/recorded. Storyboard:
  `reports/video-script.md`.
- Duration target: 6:30–8:00 (script's target), within the organizer's
  5–10 minute window (`docs/participant-guide.md`).
- Capture not yet done — real-agent (`ollama:qwen3:8b`) recording is
  scheduled for ~15:00–17:30 on the desktop rig per `progress.md`.

## Technical report

- Location: `reports/technical-report.md`.
- Restructured to the official 1–10 template
  (`docs/research-report-template.md` in the starter kit) this session —
  see `progress.md` for what moved where.
- Format: Markdown, committed in the repo. **Open item**: whether the
  submission form/instructions accept a plain repo-committed `.md` or
  require a `.pdf` export could not be confirmed from anything in this
  repo or the starter kit docs (`docs/*.md` have no format guidance —
  participant-guide.md just says "no page limit," no file-type
  requirement). The actual submission link/instructions are external and
  not available to check from here. **Team: check the submission
  form/instructions directly for accepted format before 23:00.** No PDF
  export tool (`pandoc`, `weasyprint`, `wkhtmltopdf`) is currently
  installed on this machine if one turns out to be required — flag early
  enough to install one, not at 22:45.

## `sentinel submission validate` — re-run this session

**First run (before this session's fix), against
`/home/ghass/sentinel-shield/sentinel-shield`:**

```json
{
  "ok": false,
  "checks": [
    {"name": "dockerfile", "status": "fail", "detail": "Dockerfile not found at submission root"},
    {"name": "manifest", "status": "fail", "detail": "sentinel-submission.yaml not found"},
    {"name": "no_secrets", "status": "pass"},
    {"name": "no_escaping_symlinks", "status": "pass"},
    {"name": "file_sizes", "status": "pass"}
  ]
}
```

Neither file existed at the repo root — this submission would have been
rejected outright by the static check. **Fixed this session**: added a
root `Dockerfile` (uv-based, non-root `USER 10001:10001`, `EXPOSE 8080`,
mirrors the `python-defense` starter kit's shape but using `uv sync`
instead of `pip install -r requirements.txt` since this repo has no
`requirements.txt`) and `sentinel-submission.yaml` (name `sentinel-shield`,
`models: []` / `datasets: []` — the defense is rule-based with no learned
component, so nothing to declare; Qwen3-8B is the organizer-supplied agent
under test, not part of this submission).

**Re-run after the fix, same target:**

```json
{
  "ok": true,
  "checks": [
    {"name": "non_root_user", "status": "pass", "detail": "USER 10001:10001"},
    {"name": "dockerfile_privileges", "status": "pass"},
    {"name": "manifest", "status": "pass", "detail": "sentinel-shield: 0 model(s), 0 dataset(s)"},
    {"name": "no_secrets", "status": "pass"},
    {"name": "no_escaping_symlinks", "status": "pass"},
    {"name": "file_sizes", "status": "pass"}
  ]
}
```

Command (from `sentinel-starter-kit/`):

```bash
uv run sentinel submission validate /home/ghass/sentinel-shield/sentinel-shield --json
```

**Not verified this session**: the Docker image was not actually built —
`docker` is installed on this machine but the daemon isn't reachable from
this shell (WSL2/Docker Desktop backend not started here). The static
checks passing does not guarantee `docker build` succeeds. **Build and run
the image at least once before 23:00** (`docker build -t sentinel-shield .`
then hit `POST /v1/decision` inside the container) — this has not been
done yet.

## Still open before 23:00

1. Fill in `team:` in `sentinel-submission.yaml` (currently a `TODO`
   placeholder — team member names/handle not available to fill in from
   this session).
2. Confirm accepted report format (Markdown vs. PDF) against the actual
   submission instructions.
3. Build-test the Docker image at least once.
4. Video capture, filename, and final duration.
5. Final commit hash, recorded last, after all freeze-window merges land.
