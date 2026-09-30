# emirdag -00 lapse pin readiness note (W244-10, maintenance)

Draft: draft-emirdag-scitt-ai-agent-execution
Revision: 00
Lapse: 2026-10-13T20:40:30Z
Observed: 2026-09-30
Revision-checked: 00
Pin-deadline: 2026-10-10

## Status

The IETF datatracker record for `draft-emirdag-scitt-ai-agent-execution`
was fetched 2026-09-30 and reports revision `00` with
`expires: 2026-10-13T20:40:30Z`. No `-01` revision exists in the
datatracker (revision history shows only `00`; the document API object
still reads `"rev": "00"`).

The staged lapse in `gov/stale_authority.py` (`EMIRDAG_LAPSE_UTC`) matches
this expiry exactly, so the `stale-authority` refusal fires on the pinned
instant with no code change needed. The `-01`-conditional branch of
W244-10 was not taken.

## Plan

If no `-01` revision is posted by 2026-10-10, pin the `-00` draft text
into the repo so post-lapse evidence referencing it stays auditable
against the exact lapsed bytes. If a `-01` appears before then, update
`gov/stale_authority.py`'s emirdag entry to the new expiry with a comment
citing the source URL and fetch date, and re-record this note.

## Sources

- https://datatracker.ietf.org/doc/draft-emirdag-scitt-ai-agent-execution/
- https://datatracker.ietf.org/doc/draft-emirdag-scitt-ai-agent-execution/
  history/
