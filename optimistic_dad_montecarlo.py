#!/usr/bin/env python3

"""
Monte‑Carlo simulation for the identifier‑collision algorithm described in the
conversation.  It lets you explore how the parameters affect the time until all
participants hold unique identifiers.

Identifiers are integers in the range 0 … M (inclusive).  There are N
participants.  Whenever two or more participants share the same identifier, any
individual member of that collision group redraws with independent probability
q (0 < q ≤ 1).  A redraw means picking a fresh identifier uniformly at random
from 0 … M.

--------------------------------------------------------------------------
COMMAND‑LINE USAGE
--------------------------------------------------------------------------
Run the module as a script to launch a quick experiment in the terminal, e.g.::

    python id_collision_sim.py --trials 50000 --N 50 --M 999 --q 0.50 --K 5

This prints
  * the average number of seconds (steps) until convergence;
  * the probability that convergence finished within K steps (if K is given);
  * a small histogram of the observed step counts.

--------------------------------------------------------------------------
EMBEDDING IN A NOTEBOOK OR OTHER PYTHON CODE
--------------------------------------------------------------------------
>>> from id_collision_sim import run_sim, sweep_q
>>> stats = run_sim(trials=10000, N=30, M=200, q=0.5, K=6)
>>> print(stats["mean_steps"], stats["prob_within_K"])  # etc.

To compare several candidate q values in one go:

>>> qs = [0.25, 0.5, 0.75, 1.0]
>>> rows = sweep_q(trials=20000, N=30, M=200, q_values=qs, K=6)
>>> for q, mean_steps, p_within in rows:
...     print(f"q={q:4.2f}  mean={mean_steps:5.2f}  P(T<=6)={p_within:6.3f}")

--------------------------------------------------------------------------
DEPENDENCIES
--------------------------------------------------------------------------
Only the Python standard library is needed (``random``, ``argparse``,
``statistics``, ``collections``).
"""

import random
import argparse
import statistics
from collections import Counter
from typing import List, Tuple, Optional, Dict

################################################################################
# Core simulation helpers
################################################################################

def simulate_once(
    N: int,
    M: int,
    q: float,
    max_steps: int = 10_000,
    *,
    _rand: random.Random = random,
) -> int:
    """Run one realisation of the process.

    Returns
    -------
    steps : int
        Number of seconds until every participant has a unique identifier.
        *0* means the initial random draw was already collision‑free.

    Raises
    ------
    RuntimeError
        If *max_steps* is exceeded – indicates unusual parameter choices.
    """
    # Draw initial identifiers
    ids: List[int] = [_rand.randint(0, M) for _ in range(N)]

    for step in range(max_steps + 1):  # step = 0 is the initial state
        if len(set(ids)) == N:
            return step  # convergence achieved

        # Count occurrences of each identifier
        counts: Counter = Counter(ids)

        # Each colliding participant decides independently whether to redraw
        for i, ident in enumerate(ids):
            if counts[ident] > 1 and _rand.random() < q:
                ids[i] = _rand.randint(0, M)

    raise RuntimeError("Maximum steps exceeded – algorithm did not converge.")


def run_sim(
    trials: int,
    N: int,
    M: int,
    q: float,
    K: Optional[int] = None,
    *,
    seed: Optional[int] = None,
) -> Dict[str, object]:
    """Run *trials* independent simulations and collect summary statistics.

    Parameters
    ----------
    trials : int
        Number of Monte‑Carlo runs.
    N, M, q : see :pyfunc:`simulate_once`.
    K : int, optional
        If provided, also compute the probability that the process terminates
        within *K* steps.
    seed : int, optional
        Seed for the PRNG so results are reproducible.
    """
    if seed is not None:
        rnd = random.Random(seed)
    else:
        rnd = random

    steps_list: List[int] = [simulate_once(N, M, q, _rand=rnd) for _ in range(trials)]

    mean_steps = statistics.fmean(steps_list)
    prob_within_K = None if K is None else sum(s <= K for s in steps_list) / trials

    return {
        "mean_steps": mean_steps,
        "prob_within_K": prob_within_K,
        "distribution": steps_list,
    }

################################################################################
# Convenience: sweep a range of q values
################################################################################

def sweep_q(
    trials: int,
    N: int,
    M: int,
    q_values: List[float],
    K: Optional[int] = None,
    *,
    seed: Optional[int] = None,
) -> List[Tuple[float, float, Optional[float]]]:
    """Evaluate several q parameters with identical settings.

    Returns a list of (q, mean_steps, prob_within_K) tuples sorted by *q*.
    """
    rows = []
    for q in q_values:
        stats = run_sim(trials, N, M, q, K, seed=seed)
        rows.append((q, stats["mean_steps"], stats["prob_within_K"]))
    return rows

################################################################################
# Command‑line interface
################################################################################

def _cli():
    parser = argparse.ArgumentParser(
        description="Monte‑Carlo exploration of the identifier‑collision protocol",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--trials", type=int, default=10_000, help="number of Monte‑Carlo runs")
    parser.add_argument("--N", type=int, required=True, help="number of participants")
    parser.add_argument("--M", type=int, required=True, help="identifiers range 0 … M")
    parser.add_argument("--q", type=float, default=0.25, help="redraw probability for a colliding node (0<q≤1)")
    parser.add_argument("--K", type=int, default=None, help="report probability that convergence ≤ K steps")
    parser.add_argument("--seed", type=int, default=None, help="PRNG seed for reproducibility")

    args = parser.parse_args()

    stats = run_sim(args.trials, args.N, args.M, args.q, args.K, seed=args.seed)

    print("\n===== Monte‑Carlo results =====")
    print(f"trials                     : {args.trials}")
    print(f"participants (N)           : {args.N}")
    print(f"identifier max (M)         : {args.M}")
    print(f"redraw probability (q)     : {args.q}")
    print(f"average steps to converge  : {stats['mean_steps']:.3f}")
    if args.K is not None:
        print(f"P(converge ≤ {args.K} steps) : {stats['prob_within_K']:.4f}")

    # Small histogram up to the 99th percentile for a quick visual check
    from math import ceil
    cutoff = ceil(statistics.quantiles(stats["distribution"], n=100)[98])
    hist = Counter(s for s in stats["distribution"] if s <= cutoff)
    print("\nstep  runs (≤99th percentile)")
    for step in range(max(hist) + 1):
        bar = "*" * (hist[step] * 50 // max(hist.values())) if hist else ""
        print(f"{step:4d}  {hist[step]:6d} {bar}")


if __name__ == "__main__":
    _cli()
