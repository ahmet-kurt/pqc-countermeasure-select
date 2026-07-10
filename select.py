#!/usr/bin/env python3
"""
Reference implementation of the constraint-based countermeasure selection
framework of:

  "Selecting Lightweight Side-Channel Countermeasures for Embedded
   Post-Quantum Cryptography: A Constraint-Based Framework"

The script evaluates a deployment descriptor

    D = (A, S, L_k, R_o, B_c, B_m, B_r)

against the cost priors of Table I (published Cortex-M measurements), applies
the coverage and resource-feasibility rules of Section IV-B, ranks the
resource-feasible candidates by the normalized budget-utilization objective
J(s) of Section IV-A, and reports the selected stack together with its
required evidence level (Section IV-C).  The Section V worked examples
(grid, battery, signer) are included as presets and as self-tests (--check).

Usage:
    python select.py --example grid       # Section V-A worked example
    python select.py --example battery    # Section V-B worked example
    python select.py --descriptor d.json  # arbitrary descriptor (JSON)
    python select.py --check              # self-test against the paper's numbers

No dependencies beyond the Python 3.8+ standard library.
"""

import argparse
import itertools
import json
import math
import sys

# ---------------------------------------------------------------------------
# Table I cost priors (published Cortex-M measurements, with provenance).
# Cycle counts are per ML-KEM-768 decapsulation.  pqm4 figures were read from
# benchmarks.md at commit cc2c1b99 (accessed 2026-07-12).
# ---------------------------------------------------------------------------

PRIORS = {
    "pqm4_m4fspeed": {
        "kind": "baseline",
        "cycles": 707_827,          # pqm4 benchmarks.md (AVG), commit cc2c1b99
        "stack_bytes": 6_452,       # pqm4 benchmarks.md, decapsulation stack
        "rand_bytes": 0,            # unprotected: no masking randomness
        "source": "pqm4 repository [kannwischer2019pqm4, pqm4repo]",
    },
    "pqm4_m4fstack": {
        "kind": "baseline",
        "cycles": 714_194,          # pqm4, stack-optimized variant (AVG)
        "stack_bytes": 2_844,
        "rand_bytes": 0,
        "source": "pqm4 repository [pqm4repo]",
    },
    # First-order masked ML-KEM-768/Kyber768 decapsulation candidates.
    # Both cycle counts were measured on an STM32F407 whose hardware TRNG
    # supplied the masking randomness, i.e. generation is already included
    # in the cycles ("rand_in_cycles").
    "masked1_heinz": {
        "kind": "L4_order1",
        "cycles": 2_978_441,        # includes on-chip RNG sampling
        "rand_bytes": 12_072,       # class prior taken from Bos et al. Table 2
        "rand_in_cycles": True,
        "rand_note": "randomness demand not reported separately; "
                     "class prior from [bos2021masking]",
        "source": "Heinz et al. [heinz2022masked]",
    },
    "masked1_bos": {
        "kind": "L4_order1",
        "cycles": 3_116_000,        # TCHES Table 2, reported to nearest 10^3
        "rand_bytes": 12_072,       # TCHES Table 2, #randombytes, 1st order
        "rand_in_cycles": True,
        "source": "Bos et al. [bos2021masking]",
    },
    # Higher-order prior (authors state it is not aggressively optimized).
    "masked2_bos": {
        "kind": "L4_order2",
        "cycles": 44_347_000,       # TCHES Table 2, 2nd order
        "rand_bytes": 902_126,      # TCHES Table 2, #randombytes, 2nd order
        "rand_in_cycles": True,
        "source": "Bos et al. [bos2021masking] (not aggressively optimized)",
    },
    # ML-DSA/Dilithium3 signing (Azouaoui et al., STM32L4R5 Cortex-M4,
    # Section 6.3: masked cycle counts include TRNG randomness; single
    # execution of the rejection-sampling loop).  No RAM or random-byte
    # totals are reported; the structural RAM prior attaches to the pqm4
    # stack-optimized signing stack (6,616 B), a different code base,
    # so treat memory results as coarse.
    "pqm4_dilithium3_sign": {
        "kind": "baseline", "op": "sign",
        "cycles": 3_224_000,        # unprotected reference quoted by Azouaoui
        "stack_bytes": 6_616,       # pqm4 ml-dsa-65 m4fstack signing stack
        "rand_bytes": 0,
        "source": "pqm4 via Azouaoui et al. [azouaoui2023dilithium]",
    },
    "masked1_dilithium3_rand": {
        "kind": "L4_order1", "op": "sign",
        "cycles": 14_282_000,       # 2-share randomized signing
        "rand_bytes": 0,            # not reported; randomness in cycles
        "rand_in_cycles": True,
        "source": "Azouaoui et al. [azouaoui2023dilithium]",
    },
    "masked1_dilithium3_det": {
        "kind": "L4_order1", "op": "sign",
        "cycles": 24_005_000,       # 2-share deterministic signing
        "rand_bytes": 0,
        "rand_in_cycles": True,
        "source": "Azouaoui et al. [azouaoui2023dilithium]",
    },
}

# Structural prior for the RAM of a masked implementation: none of the cited
# masked implementations report RAM, so the framework uses a conservative
# multiplier on the measured unprotected stack (two shares for every
# sensitive intermediate plus conversion buffers) and flags the figure for
# on-target confirmation.  See Section V-A and the benchmarking gap in
# Section VI.
MASKED_STACK_FACTOR = {1: 3.0, 2: 5.0}

# Coarse layer priors for the cheap layers (Section III).
L2_CYCLE_FACTOR = 1.05   # hiding: "a few percent"
L3_CYCLE_FACTOR = 1.20   # shuffling: "tens of percent" [ravi2024survey]
L3_RAND_BYTES = 1_024    # coarse prior: per-op permutation randomness
L3_STACK_BYTES = 256     # coarse prior: permutation buffer

EVIDENCE = {1: "E1", 2: "E2", 3: "E3", 4: "E4", 5: "E5"}


# ---------------------------------------------------------------------------
# Coverage rules (Sections II-C and IV-B)
# ---------------------------------------------------------------------------

def required_coverage(A, S):
    """Gamma(A, S): the leakage classes the deployment must cover.

    A remote-only adversary (A1) observes no power or EM channel, so only
    timing needs coverage regardless of sophistication (Section II-C).
    """
    if A == "A1":
        return {"T"}
    if S == "S2":
        return {"T", "D", "P"}
    return {"T", "D"}


def coverage_feasible(stack, gamma):
    """Section IV-B: every class in gamma needs a primary countermeasure.

    Returns (ok, pending_E4): class P via first-order L4+L3 is admitted only
    as a candidate subject to an E4 profiled-attack evaluation.
    """
    pending_e4 = False
    if "T" in gamma and "L1" not in stack.layers:
        return False, False
    if "D" in gamma and stack.mask_order < 1:
        return False, False
    if "P" in gamma:
        if stack.mask_order >= 2:
            pass                                   # order >= 2 qualifies
        elif stack.mask_order == 1 and "L3" in stack.layers:
            pending_e4 = True                      # candidate pending E4
        else:
            return False, False
    return True, pending_e4


def exposure_advisory(d):
    """Section IV-A: N_k = R_o * L_k sizes the L5 exposure-control policy.

    The rule keeps the per-key trace budget at least an order of magnitude
    below the smallest published class-D attack trace count for the chosen
    implementation.  That count is implementation- and setup-specific threat
    intelligence, so it is supplied by the caller as `attack_traces_D`
    rather than baked in as a prior.
    """
    if not d.get("L_k"):
        return None
    adv = {"N_k": d["R_o"] * d["L_k"]}
    if d.get("attack_traces_D"):
        adv["N_k_max"] = 0.1 * d["attack_traces_D"]
        adv["L_k_max"] = adv["N_k_max"] / d["R_o"]
        adv["rule_ok"] = adv["N_k"] <= adv["N_k_max"]
    return adv


def evidence_level(stack, gamma, pending_e4):
    """Section IV-C: the evidence the selected stack must carry.

    An order >= 2 stack is selected here only in high-value deployments
    (Table II row C4), so it carries certification-grade E5.  A lower-threat
    use of higher-order masking would instead warrant the higher-order
    leakage-detection level E3 (Section IV-C).
    """
    if stack.mask_order >= 2:
        return "E5"
    if pending_e4:
        return "E2 + E4"
    if "D" in gamma:
        return "E2"
    return "E1"


# ---------------------------------------------------------------------------
# Candidate stacks
# ---------------------------------------------------------------------------

class Stack:
    def __init__(self, layers, baseline, masked_impl=None):
        self.layers = frozenset(layers)      # subset of {L1..L5}
        self.baseline = baseline             # key into PRIORS (unprotected)
        self.masked_impl = masked_impl       # key into PRIORS or None
        self.mask_order = (0 if masked_impl is None
                           else int(PRIORS[masked_impl]["kind"][-1]))

    @property
    def name(self):
        base = "+".join(sorted(self.layers))
        if self.masked_impl:
            base += f" [{self.masked_impl}]"
        return base

    def costs(self):
        """Compose per-operation cycles, stack bytes, and random bytes.

        Measured whole-stack costs are used where available (the masked
        implementations measure L1+L4 together); the cheap layers are
        composed multiplicatively as conservative priors (Section IV-A).
        """
        if self.masked_impl:
            cycles = PRIORS[self.masked_impl]["cycles"]
            rand = PRIORS[self.masked_impl]["rand_bytes"]
            stack_b = (PRIORS[self.baseline]["stack_bytes"]
                       * MASKED_STACK_FACTOR[self.mask_order])
            ram_is_prior = True
        else:
            cycles = PRIORS[self.baseline]["cycles"]
            rand = 0
            stack_b = PRIORS[self.baseline]["stack_bytes"]
            ram_is_prior = False
        if "L3" in self.layers:
            cycles *= L3_CYCLE_FACTOR
            rand += L3_RAND_BYTES
            stack_b += L3_STACK_BYTES
        if "L2" in self.layers:
            cycles *= L2_CYCLE_FACTOR
        return cycles, stack_b, rand, ram_is_prior


def enumerate_candidates(descriptor):
    """All stacks the framework considers for a software-only selection.

    For decapsulation, unprotected candidates may use either pqm4 variant
    (the stack-optimized variant trades <1% cycles for 2.3x less RAM); the
    masked implementations build on pqm4's speed-optimized code, so their
    RAM prior attaches to that baseline.  For signing, the randomized and
    deterministic masked implementations are coverage-equivalent candidates
    that the ranking discriminates.
    """
    extras = [set(), {"L2"}, {"L3"}, {"L2", "L3"}]
    out = []
    if descriptor.get("operation", "decaps") == "sign":
        for e in extras:
            out.append(Stack({"L1", "L5"} | e, "pqm4_dilithium3_sign", None))
        for m, e in itertools.product(
                ["masked1_dilithium3_rand", "masked1_dilithium3_det"], extras):
            out.append(Stack({"L1", "L4", "L5"} | e,
                             "pqm4_dilithium3_sign", m))
        return out
    for b, e in itertools.product(["pqm4_m4fspeed", "pqm4_m4fstack"], extras):
        out.append(Stack({"L1", "L5"} | e, b, None))
    for m, e in itertools.product(
            ["masked1_heinz", "masked1_bos", "masked2_bos"], extras):
        out.append(Stack({"L1", "L4", "L5"} | e, "pqm4_m4fspeed", m))
    return out


# ---------------------------------------------------------------------------
# Feasibility and ranking (Sections IV-A, IV-B)
# ---------------------------------------------------------------------------

def evaluate(stack, d):
    """Return a result dict with feasibility tests and J(s)."""
    cycles, stack_b, rand_b, ram_is_prior = stack.costs()
    t_op = cycles / d["clock_hz"]                       # seconds
    # On-demand randomness generation adds to per-operation latency when the
    # platform lacks a TRNG comparable to the measurement platform's (whose
    # sampling time the measured cycle counts already include); an idle-time
    # pool (an L5 measure) moves the demand to the sustained check instead,
    # with the pooled bytes charged against B_m (Section IV-B).
    rand_in_cycles = (stack.masked_impl is not None
                      and PRIORS[stack.masked_impl].get("rand_in_cycles"))
    if d.get("rand_prefetch"):
        t_rand = 0.0
        stack_b += rand_b
    elif d.get("trng_onboard") and rand_in_cycles:
        t_rand = 0.0
    else:
        t_rand = rand_b / d["B_r"]
    # ell(s): the per-operation latency of Section IV-B, which is also the
    # cycle term of the ranking objective J(s) in Section IV-A.
    lat = t_op + t_rand
    sustained = rand_b * d["R_o"]                       # bytes/second
    tests = {
        "latency": lat <= d["B_c"],
        "memory": stack_b <= d["B_m"],
        "randomness": sustained <= d["B_r"],
    }
    w = d.get("weights", {"c": 1 / 3, "m": 1 / 3, "r": 1 / 3})
    J = (w["c"] * lat / d["B_c"]
         + w["m"] * stack_b / d["B_m"]
         + w["r"] * sustained / d["B_r"])
    return {
        "stack": stack, "cycles": cycles, "t_op_ms": t_op * 1e3,
        "t_rand_ms": t_rand * 1e3, "latency_ms": lat * 1e3,
        "stack_bytes": stack_b, "ram_is_prior": ram_is_prior,
        "rand_bytes": rand_b, "sustained_Bps": sustained,
        "tests": tests, "feasible": all(tests.values()), "J": J,
    }


def select(d, verbose=True):
    gamma = required_coverage(d["A"], d["S"])
    rows = []
    for s in enumerate_candidates(d):
        cov_ok, pending_e4 = coverage_feasible(s, gamma)
        if not cov_ok:
            continue
        r = evaluate(s, d)
        r["pending_e4"] = pending_e4
        r["evidence"] = evidence_level(s, gamma, pending_e4)
        rows.append(r)
    feasible = [r for r in rows if r["feasible"]]
    feasible.sort(key=lambda r: r["J"])

    if verbose:
        print(f"Required coverage Gamma(A,S) = {sorted(gamma)}")
        adv = exposure_advisory(d)
        if adv:
            print(f"Exposure control (L5): N_k = R_o * L_k = "
                  f"{adv['N_k']:,.0f} secret-bearing invocations per key "
                  f"epoch.")
            if "L_k_max" in adv:
                print(f"  Section IV-A rule: keep N_k <= "
                      f"{adv['N_k_max']:,.0f}, i.e. re-key at least every "
                      f"{adv['L_k_max'] / 86_400:,.1f} days at this R_o "
                      f"[{'OK' if adv['rule_ok'] else 'epoch too long'}]")
            else:
                print("  Supply attack_traces_D (smallest published class-D "
                      "trace count for the chosen implementation) to size "
                      "the re-keying epoch per the Section IV-A rule.")
        print(f"{len(rows)} coverage-feasible candidate(s); "
              f"{len(feasible)} also resource-feasible\n")
        hdr = (f"{'stack':52s} {'lat[ms]':>8s} {'RAM[B]':>8s} "
               f"{'rnd[B/s]':>9s} {'feas':>5s} {'J':>7s}  evidence")
        print(hdr)
        print("-" * len(hdr))
        for r in sorted(rows, key=lambda r: (not r["feasible"], r["J"])):
            fail = ",".join(k for k, v in r["tests"].items() if not v)
            print(f"{r['stack'].name:52s} {r['latency_ms']:8.1f} "
                  f"{r['stack_bytes']:8.0f} {r['sustained_Bps']:9.1f} "
                  f"{'yes' if r['feasible'] else 'NO':>5s} {r['J']:7.3f}  "
                  f"{r['evidence']}"
                  + (f"  [violates: {fail}]" if fail else "")
                  + ("  (RAM is a structural prior)" if r["ram_is_prior"]
                     else ""))
        print()
    if not feasible:
        if verbose:
            print("No feasible stack; escalate per Algorithm 1: reduce R_o "
                  "or restructure via L5 (e.g., session resumption, idle-time "
                  "randomness pooling), move the operation off the latency-"
                  "critical path, add clock/acceleration, relocate the "
                  "secret, or adopt protected hardware; then rerun.")
        return None, rows
    best = feasible[0]
    if verbose:
        print(f"Selected: {best['stack'].name}")
        print(f"  J = {best['J']:.3f}; evidence required: {best['evidence']}")
        if best["pending_e4"]:
            print("  NOTE: class-P coverage is provisional pending the E4 "
                  "profiled-attack evaluation; on E4 failure escalate to "
                  "order >= 2 or hardware isolation.")
        if best["ram_is_prior"]:
            print("  NOTE: masked RAM figure is a conservative structural "
                  "prior (no cited masked implementation reports RAM); "
                  "confirm on target.")
    return best, rows


# ---------------------------------------------------------------------------
# Section V worked examples as descriptors
# ---------------------------------------------------------------------------

EXAMPLES = {
    # Section V-A: mains-powered smart grid controller (matches row C3).
    "grid": {
        "A": "A3", "S": "S2",
        "clock_hz": 100e6,
        "L_k": 15 * 365 * 24 * 3600,  # 15-year deployment: the upper bound
                                  # on the key epoch if never re-keyed; the
                                  # exposure advisory motivates L5 rotation
        "R_o": 4 / 3600,          # a few handshakes per hour
        "B_c": 100e-3,            # 100 ms decapsulation latency budget
        "B_m": 32 * 1024,         # 32 KiB crypto RAM budget (128 KiB part)
        "B_r": 100 * 1024,        # hardware TRNG, >= 100 KiB/s sustained
        "trng_onboard": True,     # F407-class TRNG: sampling already in cycles
        "rand_prefetch": False,
        "weights": {"c": 0.5, "m": 0.25, "r": 0.25},
    },
    # Section V-C: on-device ML-DSA signing (grid controller signing
    # measurements; meter-reporting latency budget).  Tightening B_c to a
    # protection-relay trip path (tens of ms) makes every masked candidate
    # infeasible and triggers escalation to hardware (row C4).
    "signer": {
        "A": "A2", "S": "S1",
        "operation": "sign",
        "clock_hz": 100e6,
        "R_o": 12 / 3600,
        "B_c": 200e-3,            # 200 ms signing latency budget
        "B_m": 32 * 1024,
        "B_r": 100 * 1024,
        "trng_onboard": True,
        "rand_prefetch": False,
        "weights": {"c": 0.5, "m": 0.25, "r": 0.25},
    },
    # Section V-B: latency-constrained battery endpoint.  The synthetic
    # TRNG scenario: no TRNG peripheral; a conditioned noise source delivers
    # ~16 KiB/s, and randomness is generated on demand.
    "battery": {
        "A": "A2", "S": "S1",
        "clock_hz": 48e6,
        "R_o": 12 / 3600,
        "B_c": 50e-3,             # 50 ms decapsulation latency budget
        "B_m": 24 * 1024,         # 24 KiB crypto RAM budget: the masked-RAM
                                  # prior (~18.9 KiB) fits but is near-saturated
        "B_r": 16 * 1024,         # synthetic: 16 KiB/s entropy source
        "trng_onboard": False,    # no TRNG peripheral: on-demand generation
        "rand_prefetch": False,
        "weights": {"c": 0.5, "m": 0.25, "r": 0.25},
    },
}


def run_checks():
    """Assert the numbers quoted in Section V."""
    ok = True

    def check(label, cond):
        nonlocal ok
        print(("PASS" if cond else "FAIL") + "  " + label)
        ok = ok and cond

    # Latency arithmetic quoted in the paper.
    check("Heinz masked decaps @100 MHz ~ 29.8 ms",
          abs(2_978_441 / 100e6 * 1e3 - 29.8) < 0.05)
    check("Bos masked decaps @100 MHz ~ 31.2 ms",
          abs(3_116_000 / 100e6 * 1e3 - 31.2) < 0.05)
    check("pqm4 unprotected @100 MHz ~ 7.1 ms",
          abs(707_827 / 100e6 * 1e3 - 7.1) < 0.05)
    check("Heinz masked decaps @48 MHz ~ 62.1 ms",
          abs(2_978_441 / 48e6 * 1e3 - 62.1) < 0.05)

    # Grid example: a feasible candidate exists, Heinz-instantiated
    # L4+L3 stack wins the ranking, evidence E2+E4.
    best, _ = select(EXAMPLES["grid"], verbose=False)
    check("grid: feasible candidate exists", best is not None)
    if best:
        check("grid: winner instantiates L4 with Heinz et al.",
              best["stack"].masked_impl == "masked1_heinz")
        check("grid: winner covers P via L4+L3 pending E4",
              best["pending_e4"] and "L3" in best["stack"].layers)
        check("grid: evidence E2 + E4", best["evidence"] == "E2 + E4")
        check("grid: L2-augmented variant ranks below the winner",
              best["stack"].layers == frozenset(
                  {"L1", "L3", "L4", "L5"}))
    # Grid: memory prior within budget (3 x 6452 = 19,356 + 256 <= 32 KiB).
    r = evaluate(Stack({"L1", "L3", "L4", "L5"}, "pqm4_m4fspeed",
                       "masked1_heinz"), EXAMPLES["grid"])
    check("grid: masked RAM prior ~19.2 KiB within 32 KiB budget",
          r["tests"]["memory"] and 19_000 < r["stack_bytes"] < 20_000)
    check("grid: sustained randomness ~13.4 B/s",
          abs(evaluate(Stack({"L1", "L4", "L5"}, "pqm4_m4fspeed",
                             "masked1_bos"),
                       EXAMPLES["grid"])["sustained_Bps"] - 13.4) < 0.1)
    # Exposure-control sizing (Section IV-A): N_k = R_o * L_k.
    adv = exposure_advisory(EXAMPLES["grid"])
    check("grid: N_k = 525,600 invocations if never re-keyed over 15 years",
          adv is not None and abs(adv["N_k"] - 525_600) < 1)
    adv2 = exposure_advisory(dict(EXAMPLES["grid"], attack_traces_D=100_000))
    check("grid: synthetic 100k-trace class-D prior caps the key epoch at "
          "~104 days", adv2["rule_ok"] is False
          and abs(adv2["L_k_max"] / 86_400 - 104.17) < 0.05)
    # Gamma(A1, S2) = {T}: remote-only adversaries have no power/EM channel.
    check("coverage: Gamma(A1, S2) = {T}",
          required_coverage("A1", "S2") == {"T"})

    # Battery example: no feasible candidate; both latency and on-demand
    # randomness bind independently.
    best_b, rows_b = select(EXAMPLES["battery"], verbose=False)
    check("battery: no feasible candidate (escalate)", best_b is None)
    rb = evaluate(Stack({"L1", "L4", "L5"}, "pqm4_m4fspeed",
                        "masked1_heinz"), EXAMPLES["battery"])
    check("battery: cycles alone ~62.1 ms > 50 ms",
          rb["t_op_ms"] > 50)
    check("battery: on-demand randomness ~0.74 s at 16 KiB/s",
          abs(rb["t_rand_ms"] - 736.8) < 1.0)
    # After L5 restructuring (session resumption moves full decapsulation
    # off the latency-critical path), the relaxed budget absorbs on-demand
    # generation; an in-RAM randomness pool instead violates B_m.
    d2 = dict(EXAMPLES["battery"], B_c=1.0)
    best2, _ = select(d2, verbose=False)
    check("battery: L5 restructuring restores feasibility "
          "(resumption; off-path budget absorbs on-demand randomness)",
          best2 is not None)
    rp = evaluate(Stack({"L1", "L4", "L5"}, "pqm4_m4fspeed",
                        "masked1_heinz"),
                  dict(EXAMPLES["battery"], rand_prefetch=True))
    check("battery: pooled randomness charged to memory exceeds B_m "
          "(18.9 KiB + 11.8 KiB > 24 KiB)", not rp["tests"]["memory"])

    # Signing example: randomized masked signing wins the ranking at the
    # meter-reporting budget; a trip-path budget forces escalation.
    best_s, _ = select(EXAMPLES["signer"], verbose=False)
    check("signer: feasible at 200 ms budget", best_s is not None)
    if best_s:
        check("signer: ranking selects randomized over deterministic",
              best_s["stack"].masked_impl == "masked1_dilithium3_rand")
        check("signer: masked randomized signing ~142.8 ms at 100 MHz",
              abs(best_s["t_op_ms"] - 142.8) < 0.1)
    best_t, _ = select(dict(EXAMPLES["signer"], B_c=20e-3), verbose=False)
    check("signer: trip-path budget (20 ms) forces escalation",
          best_t is None)

    print("\nAll checks passed." if ok else "\nSOME CHECKS FAILED.")
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--example", choices=sorted(EXAMPLES))
    g.add_argument("--descriptor", metavar="FILE",
                   help="JSON file with descriptor fields "
                        "(A, S, clock_hz, R_o, B_c, B_m, B_r, weights, "
                        "trng_onboard, rand_prefetch; optionally L_k and "
                        "attack_traces_D for the exposure advisory)")
    g.add_argument("--check", action="store_true")
    args = ap.parse_args()

    if args.check:
        sys.exit(run_checks())
    d = (EXAMPLES[args.example] if args.example
         else json.load(open(args.descriptor)))
    print(f"Descriptor: {json.dumps({k: v for k, v in d.items()}, default=str)}\n")
    select(d)


if __name__ == "__main__":
    main()
