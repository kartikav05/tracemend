# Detection rules

TraceMend ships five deterministic, rule-based detectors that run over the normalized event list of one trace and report the inefficiencies they can prove from citable call ids.

[← Back to README](../README.md) · [Fix workflow](./fix-workflow.md) · [Setup](./setup.md)

## The five detectors at a glance

Every detector reads one `TraceRun` and returns `Finding` records.
There is no language model, no network access, no filesystem access and no randomness involved, so the same run always produces the same findings, in the same order, with the same ids.
They never fabricate a value: a metric that is absent from the trace is reported as `null`, and the finding says so in its `details.limitations`.

Run and per-tool duration, token and cost figures sum only recorded values. A partial
sum is not a complete total; analysis and comparison notes identify missing coverage.
Zero remains a real recorded value, distinct from `null`. Summed tool duration is not
wall-clock elapsed time. Failure counts include recorded errors only; unknown outcomes
are not successes. The duplicate-call metric counts repeated argument fingerprints,
including legitimate retries and re-verification, rather than proven waste. Comparisons
of partial sums cannot establish savings or improved task outcomes.

| Code | Detection | Severity | Evidence used | Fixable |
|---|---|---|---|---|
| **TM001** | Duplicate tool calls — the same non-read, non-search call repeated with an identical canonicalized argument hash | Scales with redundant count (`high` at 5+, `medium` at 3+, `low` otherwise) | Normalized tool name, canonical argument hash, call ids, intervening writes/reads for the touched paths | Yes |
| **TM002** | Failed retry loops — the same call failing two or more times with unchanged arguments | `high` (3+ identical failures), lower otherwise | Call ids, `status == "error"`, argument hash, recorded error text | Yes |
| **TM003** | Repeated file reads — several reads of one file with no observable modification in between | From the shared ladder; confidence drops to `low` when the trace carries no modification data at all | Read call ids, normalized path, edit/write events that touch the same path | Yes |
| **TM004** | Redundant search patterns — identical searches, plus broad searches already covered by a narrower one in the same scope | Scales with redundant count for repeated searches; `low` for a broad search already covered | Tool, normalized pattern, search scope/path, result fingerprints when present | Yes |
| **TM005** | Tool execution hotspots — tools dominating call count (≥5), failures (≥3) or observed time (≥40% share) | `info` (informational, `fixable: false`) | Call counts, failure counts, durations, tokens/cost when present | No |

Severity and confidence are separate axes, and the three detection rules that share a redundancy ladder (TM001, TM003, TM004) deliberately decouple them: 3–4 redundant calls are `medium` severity but `high` confidence, while a single redundant call is `low` severity and `medium` confidence.
See [How to read a finding](#how-to-read-a-finding).

## Ownership — why the same waste is never reported twice

Ownership is defined so the detectors never double-report the same call:

- Non-failing reads belong to TM003.
- Non-failing search-like calls — the normalized tool is `grep`/`glob`, or the call carries a `pattern`/`query` argument — belong to TM004.
- Repeated failures belong to TM002, because a repeated failure is a retry-discipline problem rather than a general duplicate-call problem.
- Everything else falls to TM001.

As a consequence TM001, TM003 and TM004 never cite the same call ids, and every finding cites real call ids from the run — a group without citable evidence is dropped instead of reported.
TM005 is explicitly an observation about where a session spent effort, not a verdict that the work was wasted.

## TM001 — Duplicate tool calls

**What it detects.**
The same non-read, non-search call repeated within one run with an identical canonicalized argument fingerprint.
Calls are grouped by `call_fingerprint` (tool plus canonicalized arguments, ignoring agent and timing information), and any group of two or more is reported.

**What it is not.**
Failing calls are excluded here — a repeated failure is TM002's job.
Read-like calls (normalized tool `read`) go to TM003, and search-like calls go to TM004.

**Evidence it cites.**
The call ids of the repeats only (`calls[1:]`), the group size and redundant count, the `call_fingerprint`, the normalized tool, and — when the trace provides them — the touched paths, the set of agent ids, and any mitigation notes.

**Example of the pattern.**

```bash
# the same command issued four times with byte-identical arguments
$ git status --short   # call_024
$ git status --short   # call_027
$ git status --short   # call_028
$ git status --short   # call_029
```

Analysing `examples/inefficient_run.json` captures this group as `TM001:bash:7557ab371a31` ("Duplicate bash calls (4x)", `medium`/`high`), citing `call_027`, `call_028`, `call_029`.

**What it deliberately does not flag.**

- The first call in a group is treated as legitimate and is never cited as evidence.
- Read-like and search-like calls, which belong to TM003 and TM004.
- Any call with `status == "error"`, which belongs to TM002.
- A call group of one — a single call is never a duplicate.

**Limitation.**
Not every repeat is waste, and the detector says so rather than assuming the worst.
If a successful write touched one of the group's paths *before* the later repeats, those repeats may be legitimate re-verification of changed state, so TM001 steps severity down one level (never below `low`), lowers confidence one step, and records a `mitigations` note explaining which write intervened.
A group spanning several agents also lowers confidence, because a subagent may legitimately repeat a parent agent's call.

## TM002 — Failed retry loop

**What it detects.**
The same invocation failing two or more times with identical arguments — the signature of an unguided retry loop.
Failures are grouped by the same `call_fingerprint` used elsewhere, so an changed argument breaks the loop.

**Evidence it cites.**
The call ids of every failure in the group, the failure count, the `call_fingerprint`, the normalized tool, and the recorded error text — a truncated preview of the last error, plus the first error when it differs.

**Example of the pattern.**

```bash
$ python -m pytest tests/test_payments.py   # call_005  → 4 failed, 2 passed in 1.82s
$ python -m pytest tests/test_payments.py   # call_006  → 4 failed, 2 passed in 1.79s
$ python -m pytest tests/test_payments.py   # call_007  → 4 failed, 2 passed in 1.84s
```

**What it deliberately does not flag.**

- Two or more failures always report, but a single failure is not a loop and is never flagged.
- Calls that failed once and then succeeded, or failed with different arguments each time — the argument fingerprint has to match.

**Severity ladder.**
Three or more identical failures are `high` severity and `high` confidence; exactly two are `low` severity and `medium` confidence.
A group spanning several agents lowers confidence one step.

**Limitation.**
A repeated error is not proof of a mistake.
Transient external failures — a flaky service, a locked file, a network blip — can also produce identical repeated errors, so the finding states plainly that the observation alone does not prove the agent handled the failure incorrectly.
It describes the retry shape, not the intent.

### Captured output

Analysing `examples/inefficient_run.json` produces this finding verbatim.
The detector code names the category; the `id` is unique *within* a run, so two different runs can both contain a `TM002:bash:...` finding without colliding.

```json
{
  "id": "TM002:bash:532575068ce1",
  "code": "TM002",
  "run_id": "run_bddb7682c206",
  "severity": "high",
  "confidence": "high",
  "title": "Repeated failing bash call (3x)",
  "description": "The same bash invocation failed 3 times with identical arguments and no change in between. This pattern is consistent with an unguided retry loop; note that transient external failures can also cause repeated errors, so this observation alone does not prove the agent handled the failure incorrectly.",
  "tool": "bash",
  "occurrences": 3,
  "evidence": ["call_005", "call_006", "call_007"],
  "recommendation": "Change the approach after the first failure: inspect the error, adjust the arguments or the code, and only retry when something relevant has changed. Otherwise stop and report the failure.",
  "fixable": true,
  "details": {
    "strategy": "retry_discipline",
    "call_fingerprint": "b294e5268612",
    "failure_count": 3,
    "last_error_excerpt": "4 failed, 2 passed in 1.84s",
    "first_error_excerpt": "4 failed, 2 passed in 1.82s"
  }
}
```

## TM003 — Repeated file reads

**What it detects.**
Several reads of the same file page with no observable modification in between.
Reads are grouped per normalized path and recorded pagination arguments into windows.
Different `offset`/`limit`/`range` values are not treated as identical coverage;
malformed ranges cannot establish redundancy. Missing pagination is explicitly uncertain.
A successful write or edit touching the path closes the window. An unknown-outcome
write also closes it conservatively, without claiming a change occurred; a failed
write does not establish a modification.

**Evidence it cites.**
The call ids of the redundant reads (`window[1:]`), the normalized path, the window size and redundant-read count, and two explicit booleans: whether the run recorded any modification data at all, and whether it recorded a modification of this specific file.

**Example of the pattern.**

```bash
$ read src/payments.py   # call_003
$ read src/payments.py   # call_004   ← no edit landed in between
$ read src/payments.py   # call_009
$ read src/payments.py   # call_014
```

Analysing `examples/inefficient_run.json` captures this window as `TM003:read:a255e6d624ab` ("Repeated reads of src/payments.py (4x)", `medium`/`medium`): pagination coverage is not recorded.

**What it deliberately does not flag.**

- The first read of each window is treated as legitimate and is never cited as evidence.
- Reads that follow a write or edit to the same path — the window is reset, so re-reading changed content is expected.
- Failed reads, which never enter a window.
- Different pages or uninterpretable ranges, which cannot prove repeated coverage.

**Limitation.**
The rule is only as strong as the trace's modification data, and it lowers its own confidence accordingly.
When the trace records no file-modification data anywhere, confidence drops to `low` and the finding states that it cannot be proven the content stayed the same — the file may have changed on disk without being recorded.
When the trace has modification data but none of it touches this file, confidence drops one step and the finding states that the file is *treated as* unchanged between these reads.
Unknown coverage and reads spanning several agents reduce confidence; an edit elsewhere
does not prove that a read covered the same content.

## TM004 — Redundant search patterns

**What it detects.**
Two related search redundancies.
First, identical searches — the same tool, pattern and scope issued more than once,
grouped by `call_fingerprint` within windows separated by relevant successful or
unknown-outcome writes. The first search after a possible content change is legitimate.
Second, a broad search whose pattern is a substring of an **earlier** narrower pattern
over the same scope and whose result fingerprint is identical. An intervening possible
content change prevents the earlier search from establishing reusable coverage.
Order follows the normalized event list; timestamps are not invented when absent.

**Evidence it cites.**
For repeated searches: the call ids of the repeats (`calls[1:]`), the matched ids, the normalized pattern and scope, the result fingerprints, and the redundant-search count.
For a broad-covered-by-narrower finding: the broad call id, the broad and narrow patterns, the shared scope, the narrow call id, and the identical result fingerprint.

**Example of the pattern.**

```bash
$ grep 'payment_status' src   # call_001
$ grep 'payment_status' src   # call_002
$ grep 'payment_status' src   # call_008   ← same pattern, same scope
$ grep 'payment_status' src   # call_018
$ grep 'payment_status' src   # call_022
```

In `examples/inefficient_run.json`, the successful edit at `call_015` splits this
pattern into a three-call group (`call_001`, `call_002`, `call_008`) and a two-call
group (`call_018`, `call_022`). The first search in each group is legitimate;
only `call_002`, `call_008` and `call_022` are cited as redundant searches.

**What it deliberately does not flag.**

- The first search of a group is treated as legitimate and is never cited as evidence.
- A single search, however broad.
- A broad/narrower pair whose result fingerprints differ, are missing, or whose scopes differ — the narrower search must have demonstrably returned the same results.
- Failed searches (TM002 owns repeated failures), later narrower searches, and
  searches separated by a relevant possible content change.
- A call already claimed by the repeated-search grouping, so one search is never reported twice.

**Severity ladder.**
Repeated searches follow the shared ladder: 5+ redundant searches are `high`, 3+ are `medium`, fewer are `low`.
A broad search already covered by a narrower one is fixed at `low` severity, starts
at `high` confidence (lower across agents), and always cites exactly one call.

**Limitation.**
This is a lightweight literal heuristic over normalized patterns and result fingerprints; there is no semantic similarity, embedding or stemming step, so it only catches textual containment — `payment` inside `payment_status` — never two differently worded searches that mean the same thing.
Confidence also drops one step when a repeated search spans several agents, because a subagent may legitimately repeat a parent agent's search.
When result fingerprints are missing or differ, confidence drops one step and the finding states that only the repeated arguments are known, not identical results.

## TM005 — Tool execution hotspot

**What it detects.**
Tools that dominate a session's effort by any one of three thresholds: at least 5 calls, at least 3 failures, or at least a 40% share of the observed tool time.

**Evidence it cites.**
The call ids of that tool's calls, the call count, the failure count, the share of all calls, the tool's total duration and its share of observed duration, and summed tokens/cost *when present*.

**Example of the pattern.**
Analysing `examples/inefficient_run.json` captures `TM005:bash:fbe07d688c13` ("Tool hotspot: bash") because bash accounted for 9 of 29 observed calls, 3 failures, and roughly 87% of the observed tool time.

**What it deliberately does not flag.**

- Any tool below all three thresholds.
- Nothing is marked `fixable` — a hotspot is never automatically wasteful.

**Limitation.**
TM005 is informational and never invents token or cost data.
It is fixed at `info` severity with `fixable: false`; confidence starts at `medium`
and drops when the triggering measurement has incomplete coverage. Its description
notes that a hotspot is an observation about where the session spent effort, not a
verdict that the tool use was wasted. `details.measurement_coverage` records run-wide
counts for durations, tokens, costs and known outcomes; limitations identify partial
sums and observed-time shares that cannot establish complete-run dominance.
When the trace contains no token, cost or duration data, the corresponding figures stay `null` and the finding records a `limitations` entry saying the figure was not present anywhere in the trace — it is never estimated and never reported as zero.

## Finding schema

Every finding is a stable, structured record with the same shape, defined by `Finding` in `src/tracemend/models.py`.

| Field | Type | Meaning |
|---|---|---|
| `id` | string | Unique *within* a run, derived as `CODE:tool:shorthash` |
| `code` | string | Detector category: `TM001`–`TM005` |
| `run_id` | string | Deterministic id of the analysed run |
| `severity` | `info` \| `low` \| `medium` \| `high` | How much the finding matters |
| `confidence` | `low` \| `medium` \| `high` | How strongly the evidence supports it |
| `title` | string | Short human-readable headline |
| `description` | string | What was observed, including its caveats |
| `tool` | string | Normalized tool the finding is about |
| `occurrences` | integer | Calls covered by the finding |
| `evidence` | list of strings | Real call ids, capped at the eight most relevant |
| `recommendation` | string | Suggested change to agent behaviour |
| `fixable` | boolean | Whether the finding can seed an `AGENTS.md` proposal |
| `details` | object | Detector-specific evidence, plus `limitations`/`mitigations` when applicable |

The `code` names the detector category, while the `id` identifies one instance of it: ids are stable and unique *within* a run, so `TM002:bash:532575068ce1` in one run and `TM002:bash:532575068ce1` in another are two different findings that never collide because the enclosing `run_id` differs.

A complete captured example, produced by analysing `examples/inefficient_run.json`, is shown under [TM002](#captured-output).

## How to read a finding

- **Severity and confidence are different axes.** Severity says how much the pattern matters if it is real; confidence says how much the trace proves it. A finding can be `medium` severity and `high` confidence (three redundant calls, clearly evidenced) or `low` severity and `medium` confidence (one redundant read with missing modification data).
- **Every finding is evidence-backed.** Each one cites real call ids from the run, and a group without citable evidence is dropped rather than reported. If a figure was not in the trace, it stays `null` and the finding records a limitation instead of guessing.
- **Findings are deterministic and need no LLM.** The detectors are pure functions of the trace — no model, no network, no randomness — so the same run always yields the same findings, in the same order, with the same ids.
- **Read `details.limitations` and `details.mitigations` before acting.** They carry the detector's own honesty notes, such as missing modification data, missing result fingerprints or an intervening edit.

## Heuristics, not verdicts

The detectors are rule-based heuristics over call signatures.
There is no embedding model, no semantic similarity and no learning across runs.
That has a real cost: genuinely distinct work which merely *looks* repetitive — a command run against two different environments, or two searches that happen to return the same fingerprint — can be flagged.
Confidence levels and limitation lists exist precisely for this, so a flagged pattern should be read as "this is worth a look", not "this was wasted".

## Related

- [README](../README.md) — the overview and the end-to-end workflow.
- [Fix workflow](./fix-workflow.md) — how a fixable finding becomes an `AGENTS.md` proposal.
- [Setup](./setup.md) — install, run and configure TraceMend.
- [Status](./status.md) — what ships today and what is planned.
