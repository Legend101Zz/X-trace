"""The one definition of the per-worktree dev ID shared by env.sh, clean.sh and their tests.

IDs name build and scratch directories, so they must be short (the scratch path is length-capped)
and distinct: names longer than 12 characters keep a 7-character prefix plus a 4-character hash,
so `agent-ready-a` and `agent-ready-b` never share a directory.
"""

import hashlib
import re
import sys

MAX_ID_LENGTH = 12


def worktree_id(name: str) -> str:
    safe = re.sub(r"[^a-z0-9-]", "-", name.lower()).strip("-")
    if not safe:
        return "worktree"
    if len(safe) <= MAX_ID_LENGTH:
        return safe
    digest = hashlib.sha256(name.encode("utf-8", "surrogateescape")).hexdigest()[:4]
    return f"{safe[:MAX_ID_LENGTH - 5].rstrip('-')}-{digest}"


if __name__ == "__main__":
    print(worktree_id(sys.argv[1]))
