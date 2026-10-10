# Human usability session protocol (HUMAN-USABILITY)

Status: protocol and scoring sheet only. No session has been run. Nothing in this directory is evidence; automation
never impersonates participants, and a scorer sheet is valid only when filled in during or right after a real session
with a real, previously unfamiliar person.

## What is being measured

The requirement: real new participants observe the request entry, the intermediate steps and the outcome of a recorded
request, and use the interactions (open a recording, move through Linear, open Canvas, read the source line), correct
for at least 80 percent of the questions, within 10 minutes each. At least two participants are needed for a receipt
(`participants[]` is validated by `tools/release/check_ledger.py`); more is better.

## Setup, per participant

1. A fresh macOS arm64 or Linux x86_64 profile with the signed (or, for rehearsal, unsigned) package installed from the
   release artifact set. Rehearsal sessions are labelled rehearsal and never enter a receipt.
2. The petclinic campaign project, instrumented, with at least one recording per scenario route already captured
   (the `campaign-petclinic` CI artifact shows what such a store contains). The participant does not run the app.
3. Screen and keyboard recording on, with the participant's consent; the recording stays in private storage and only
   its SHA-256 appears in the scoring sheet.
4. A timer started when the participant first sees the viewer, stopped at the last answer or at 600 seconds.

## Tasks and the answer key

The facilitator asks each question once, reads nothing out of the UI, and does not hint. The key is fixed before the
session and is taken from the recording shown, never improvised.

| # | Question | Correct when |
|---|----------|--------------|
| Q1 | Which HTTP request is this recording of (method and route)? | method and route template named |
| Q2 | What did the application answer? | status code named |
| Q3 | Which controller method handled it? | class and method named, or the source line opened |
| Q4 | Which repository or service call happened in between? | at least one named, in the order shown |
| Q5 | Open the same recording in Canvas: which node took the longest? | the node the key names |
| Q6 | Show me where that code lives in the project. | the source file and line opened or read out |

Correct is binary per question. A question answered after a hint, or after the 600 second limit, is incorrect.
Success rate is correct answers divided by all asked answers across all participants; the threshold is 0.8.

## Scoring sheet (one JSON object per participant, kept private; reference by hash)

```json
{
  "participantId": "p01",
  "elapsedSeconds": 0,
  "correct": false,
  "answers": [{"q": "Q1", "correct": false, "hinted": false}],
  "journey": "<sha256 of the session recording>",
  "scorer": "<scorer role id, not a name>"
}
```

`correct` at participant level is true only when the participant met the per-participant bar written down before the
session (default: at least 5 of 6 questions and `elapsedSeconds <= 600`). The receipt must be signed by the
`usability-scorer` role; this repository contains no such key.

## What a failed session means

A participant who does not reach the bar stays in the denominator. Sessions are never dropped for being awkward, and
the UI is not changed between participants of one receipt. Observed confusion is written down verbatim in the sheet.
