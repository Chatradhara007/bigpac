"""Checks features.py: vectorised output == a plain per-flow reference, and live == batch."""
import os
import sys

import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import features as F  # noqa: E402


def reference(pkts, use_iat=True):
    """Straightforward per-flow version of the same features (PDF step 4 + ms rounding)."""
    pkts = [p for p in pkts if p[1] != 0]
    first_srv = next((i for i, p in enumerate(pkts) if p[1] == -1), len(pkts))
    body = list(pkts[first_srv:first_srv + F.N_BODY])
    body += [(0, 0, 0.0)] * (F.N_BODY - len(body))
    sizes = np.array([p[0] for p in body], float)
    dirs = np.array([p[1] for p in body], float)
    iats = np.log1p(np.rint(np.array([p[2] for p in body], float)))
    iats[dirs == 0] = 0
    up, down = sizes[dirs == 1], sizes[dirs == -1]
    agg = [first_srv, up.sum(), down.sum(), len(up), len(down),
           down.max() if len(down) else 0, down.mean() if len(down) else 0,
           (down >= 1200).sum()]
    if use_iat:
        agg.append(np.median(iats[dirs == -1]) if len(down) else 0)
    parts = [sizes, dirs] + ([iats] if use_iat else []) + [np.array(agg, float)]
    return np.concatenate(parts)


def random_flow(rng, n):
    first = [(1250, 1, 0.0)] + ([(1250, 1, 0.04)] if rng.random() < 0.5 else [])
    rest = [(int(rng.integers(30, 1400)), int(rng.choice([1, -1])), float(rng.exponential(5)))
            for _ in range(max(0, n - len(first)))]
    return (first + rest)[:n]


def test_matches_reference():
    rng = np.random.default_rng(0)
    for n in [1, 2, 3, 5, 14, 15, 20, 30]:
        for use_iat in (True, False):
            for _ in range(20):
                pk = random_flow(rng, n)
                got = F.features_from_packets(pk, use_iat)[0]
                np.testing.assert_allclose(got, reference(pk, use_iat), rtol=1e-5, atol=1e-4)
                assert len(got) == len(F.feature_names(use_iat))


def test_client_only_flow():
    pk = [(1250, 1, 0.0), (1250, 1, 0.1)]
    got = F.features_from_packets(pk)[0]
    assert got[F.feature_names().index("n_client_before_server")] == 2
    assert not F.ready(pk)


def test_split_initial_alignment():
    body = [(1200, -1, 30.0), (1200, -1, 0.2), (80, 1, 1.0)] + [(1200, -1, 1.0)] * 12
    one = F.features_from_packets([(1250, 1, 0.0)] + body)[0]
    two = F.features_from_packets([(1250, 1, 0.0), (1250, 1, 0.04)] + body)[0]
    k = F.feature_names().index("n_client_before_server")
    assert one[k] == 1 and two[k] == 2
    assert np.array_equal(np.delete(one, k), np.delete(two, k))


def test_ready():
    pk = [(1250, 1, 0.0), (1250, 1, 0.0)] + [(1200, -1, 1.0)] * 11
    assert not F.ready(pk)
    assert F.ready(pk + [(50, 1, 1.0)])


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print("ok ", fn.__name__)
    print(f"{len(fns)} passed")
