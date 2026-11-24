from backend.app.services.audit_integrity import compute_event_hash, verify_chain


def test_hash_chain_verification_accepts_valid_events() -> None:
    events = []
    previous = "GENESIS"
    for sequence in range(1, 4):
        payload = {
            "event_id": f"evt-{sequence}",
            "sequence": sequence,
        }
        current = compute_event_hash(payload, previous)
        events.append({
            **payload,
            "previous_event_hash": previous,
            "current_event_hash": current,
        })
        previous = current

    valid, error = verify_chain(events)
    assert valid is True
    assert error is None


def test_hash_chain_verification_detects_modified_event() -> None:
    events = []
    previous = "GENESIS"
    for sequence in range(1, 3):
        payload = {"event_id": f"evt-{sequence}", "sequence": sequence}
        current = compute_event_hash(payload, previous)
        events.append({
            **payload,
            "previous_event_hash": previous,
            "current_event_hash": current,
        })
        previous = current

    events[1]["event_id"] = "evt-modified"
    valid, error = verify_chain(events)
    assert valid is False
    assert error is not None
