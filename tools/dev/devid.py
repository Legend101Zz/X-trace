"""The one definition of the per-worktree dev ID shared by env.sh, clean.sh and their tests.

IDs name build and scratch directories, so they must be short (the scratch path is length-capped)
and distinct: a readable prefix always includes a hash of the canonical worktree path
or the explicit ID string.
"""

import hashlib
import os
import re
import sys

MAX_ID_LENGTH = 12


def worktree_id(name: str) -> str:
    if os.path.isabs(name) and os.path.exists(name):
        name = os.path.realpath(name)
    safe = re.sub(r"[^a-z0-9-]", "-", os.path.basename(name).lower()).strip("-")
    prefix = safe[:MAX_ID_LENGTH - 5].rstrip("-") or "wt"
    digest = hashlib.sha256(name.encode("utf-8", "surrogateescape")).hexdigest()[:4]
    return f"{prefix}-{digest}"


if __name__ == "__main__":
    print(worktree_id(sys.argv[1]))
