"""Verify a recording page against its requested identity and cursor."""
import re


def bound_page_end(doc, recording_key, rid, cursor, limit, previous):
    """Check the requested recording, echoed cursor and strict order across page boundaries."""
    if (doc.get(recording_key) != rid or "cursor" not in doc or doc["cursor"] != cursor
            or type(doc.get("limit")) is not int or doc["limit"] != limit
            or len(doc["events"]) > limit):
        raise ValueError("detail page identity or range mismatch")
    for event in doc["events"]:
        sequence = event.get("sequence") if isinstance(event, dict) else None
        if not isinstance(sequence, str) or not re.fullmatch(r"0|[1-9][0-9]{0,19}", sequence):
            raise ValueError("invalid detail event sequence")
        number = int(sequence)
        if not previous < number <= 2**64 - 1:
            raise ValueError("detail event order mismatch")
        previous = number
    return previous
