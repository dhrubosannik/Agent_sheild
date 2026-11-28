"""The Firestore rate-limit store is shared across application instances."""

from concurrent.futures import ThreadPoolExecutor

from backend.app.core.rate_limit import FirestoreRateLimiter


def test_budget_is_shared_across_instances(firestore_client) -> None:
    clock = lambda: 1_000_000.0  # fixed window
    instance_a = FirestoreRateLimiter(5, 60, client=firestore_client, clock=clock)
    instance_b = FirestoreRateLimiter(5, 60, client=firestore_client, clock=clock)
    results = [(instance_a if i % 2 else instance_b).hit("ip:203.0.113.7") for i in range(8)]
    assert results.count(True) == 5
    assert results[5:] == [False, False, False]
    assert FirestoreRateLimiter(5, 60, client=firestore_client, clock=clock).hit("ip:198.51.100.1") is True


def test_concurrent_hits_never_exceed_limit(firestore_client) -> None:
    clock = lambda: 2_000_000.0
    limiters = [FirestoreRateLimiter(7, 60, client=firestore_client, clock=clock) for _ in range(3)]
    with ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(lambda i: limiters[i % 3].hit("ip:192.0.2.55"), range(20)))
    assert results.count(True) == 7


def test_new_window_resets_budget(firestore_client) -> None:
    now = [3_000_000.0]
    limiter = FirestoreRateLimiter(1, 60, client=firestore_client, clock=lambda: now[0])
    assert limiter.hit("ip:192.0.2.9") is True
    assert limiter.hit("ip:192.0.2.9") is False
    now[0] += 60
    assert limiter.hit("ip:192.0.2.9") is True
