#!/usr/bin/env python3
"""
Reference implementation of the countermeasure selection framework in

  "Selecting Side-Channel Countermeasures for Post-Quantum Cryptography on
   Resource-Constrained Cyber-Physical Devices"

A deployment descriptor states the attacker and the key usage together
with the clock and the latency, memory, and randomness budgets.  Every
candidate stack is checked against the attack catalog and the budgets, and
the feasible stacks are ranked by normalized budget utilization.  The
selected stack is reported with its required evidence level.  When no stack
fits, the script names the binding constraint and tests the escalation
designs.

The costs and the attacks live in catalog.json, and the deployments of the
paper live in deployments.json.

Usage:
    python select.py --deployment smart_meter  # one preset with its designs
    python select.py --all                     # all presets and a summary
    python select.py --descriptor d.json       # arbitrary descriptor (JSON)
    python select.py --robustness              # decisions over the prior ranges
    python select.py --assumptions             # decisions under other attack assumptions
    python select.py --sweep map.csv           # data of the design-space map (Fig. 1)
    python select.py --bench                   # scalability and selection time
    python select.py --check                   # self-test against the paper

No dependencies beyond the Python 3.8+ standard library.
"""

import argparse
import copy
import itertools
import json
import math
import os
import random
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
EVIDENCE = {1: "E1", 2: "E2", 3: "E3", 4: "E4", 5: "E5"}


def load_json(name):
    with open(os.path.join(HERE, name), encoding="utf-8") as fh:
        return json.load(fh)


# ---------------------------------------------------------------------------
# Priors and the model
# ---------------------------------------------------------------------------

def nominal_priors(catalog):
    """Nominal value of every prior in the catalog."""
    pr = catalog["priors"]
    p = {k: v["value"] for k, v in pr.items()
         if isinstance(v, dict) and "value" in v}
    p["masked_stack_factor"] = {
        int(k): v["value"] for k, v in pr["masked_stack_factor"].items()
        if k.isdigit()}
    return p


def prior_ranges(catalog):
    """(name, low, high) for every prior that carries a range.

    The masked stack factors of all orders move together as one prior, so
    at each corner every factor sits at its low or its high end.
    """
    pr = catalog["priors"]
    out = [(k, v["range"][0], v["range"][1]) for k, v in pr.items()
           if isinstance(v, dict) and "range" in v]
    msf = pr["masked_stack_factor"]
    low = {int(k): v["range"][0] for k, v in msf.items() if k.isdigit()}
    high = {int(k): v["range"][1] for k, v in msf.items() if k.isdigit()}
    out.append(("masked_stack_factor", low, high))
    return out


class Model:
    """Catalog of implementations and attacks under one setting of priors."""

    def __init__(self, catalog, overrides=None):
        self.catalog = catalog
        self.impls = {i["id"]: i for i in catalog["implementations"]}
        self.verifications = catalog.get("verifications", {})
        self.attacks = catalog.get("attacks", [])
        self.p = nominal_priors(catalog)
        if overrides:
            self.p.update(overrides)

    def baseline_stack(self, operation):
        """Measured stack of the unmasked speed baseline of an operation."""
        ref = {"decaps": "pqm4_m4fspeed", "sign": "pqm4_mldsa65_m4f"}
        return self.impls[ref[operation]]["stack_bytes"]


# ---------------------------------------------------------------------------
# Candidate stacks and their costs
# ---------------------------------------------------------------------------

class Candidate:
    """One implementation of the operation plus the optional layers.

    L1 (constant-time code) and L5 (exposure control in the descriptor) are
    always present, and L4 is present when the implementation is masked.  In
    contrast, L2 (hiding), L3 (shuffling), and L6 (fault detection) are
    optional.
    """

    def __init__(self, impl, l2=False, l3=False, l6=False):
        self.impl = impl
        self.l2, self.l3, self.l6 = l2, l3, l6

    @property
    def order(self):
        return self.impl["order"]

    def layers(self):
        ls = ["L1"]
        if self.l2:
            ls.append("L2")
        if self.l3:
            ls.append("L3")
        if self.order >= 1:
            ls.append("L4")
        ls.append("L5")
        if self.l6:
            ls.append("L6")
        return ls

    @property
    def name(self):
        return "+".join(self.layers()) + " [" + self.impl["id"] + "]"


def costs(model, cand):
    """Per-operation cycles, stack bytes, and random bytes of a candidate.

    Measured whole-operation costs are used where they are available in the
    catalog, whereas the costs of the optional layers and the missing
    figures come from the priors.  A signing count of one pass covers one
    iteration of the rejection loop, so the steps that run once per
    signature are counted once and the rest of the pass is repeated.  The
    returned list names every prior that entered the result.
    """
    p, impl = model.p, cand.impl
    used = []
    if "cycles_per_iteration" in impl:
        once = impl.get("cycles_once", 0)
        cycles = once + (impl["cycles_per_iteration"] - once) * p["sign_iterations"]
    else:
        cycles = impl["cycles"]
    cycles *= p["cycle_inflation"]
    if cand.l3:
        cycles *= p["l3_cycle_factor"]
    if cand.l2:
        cycles *= p["l2_cycle_factor"]
    if cand.l6:
        cycles *= p["l6_cycle_factor"]

    if impl.get("stack_bytes") is not None:
        stack = float(impl["stack_bytes"])
    else:
        stack = (model.baseline_stack(impl["operation"])
                 * p["masked_stack_factor"][cand.order])
        used.append("stack")
    if cand.l3:
        stack += p["l3_stack_bytes"]
    if cand.l6:
        stack *= p["l6_stack_factor"]

    if impl.get("rand_bytes") is not None:
        rand = float(impl["rand_bytes"])
    elif impl.get("rand_prior"):
        rand = (model.impls[impl["rand_prior"]]["rand_bytes"]
                * p["rand_unknown_factor"])
        used.append("randomness")
    else:
        rand = 0.0
        if cand.order > 0:
            used.append("randomness not reported")
    if cand.l3:
        rand += p["l3_rand_bytes"]
    return cycles, stack, rand, used


def evaluate(model, cand, d):
    """Latency, memory, and randomness of a candidate with its tests and J(s).

    With on-demand randomness, the generation time adds to the latency.
    Most measured cycle counts already contain the time of an on-chip TRNG
    at their measurement clock, so this sum is a conservative bound.  A
    count without this time (rand_in_cycles false) pays the generation time
    even with a TRNG, because its board had none.  An idle-time pool removes
    the generation time but holds the bytes of one operation in RAM.  A
    deployment with authenticated ciphertexts also verifies the signature of
    every ciphertext before its decapsulation.  The check runs twice when
    the attacker can inject faults, since one glitch could skip a single
    check.  The checks add their cycles to the latency, and their stack
    competes with the stack of the decapsulation for the peak.
    """
    cycles, stack, rand, used = costs(model, cand)
    t_cyc = cycles / d["clock_hz"]
    t_ver = 0.0
    if d.get("verify"):
        v = model.verifications[d["verify"]]
        checks = 2 if d.get("fault") else 1
        t_ver = (checks * v["cycles"] * model.p["cycle_inflation"]
                 / d["clock_hz"])
        stack = max(stack, float(v["stack_bytes"]))
    mode = d.get("rng", "trng")
    if mode == "on_demand" or (mode == "trng"
                               and not cand.impl.get("rand_in_cycles", True)):
        t_rand = rand / d["B_r"]
    else:
        t_rand = 0.0
    if mode == "pool":
        stack += rand
    latency = t_cyc + t_ver + t_rand
    rate = rand * d["R_o"]
    tests = {"latency": latency <= d["B_c"],
             "memory": stack <= d["B_m"],
             "randomness": rate <= d["B_r"]}
    w = d.get("weights", {"c": 1 / 3, "m": 1 / 3, "r": 1 / 3})
    J = (w["c"] * latency / d["B_c"] + w["m"] * stack / d["B_m"]
         + w["r"] * rate / d["B_r"])
    return {"cand": cand, "cycles": cycles, "t_cyc": t_cyc, "t_ver": t_ver,
            "t_rand": t_rand, "latency": latency, "stack": stack,
            "rand": rand, "rate": rate, "tests": tests,
            "feasible": all(tests.values()), "J": J, "priors_used": used}


# ---------------------------------------------------------------------------
# Threat model: required classes, attack catalog, and coverage
# ---------------------------------------------------------------------------

def exposure(d):
    """N_k, the secret-bearing operations per key epoch.

    An ephemeral key serves a single key establishment (SP 800-227), so its
    exposure is one operation.
    """
    if d.get("key_usage", "static") == "ephemeral":
        return 1.0
    return d["R_o"] * d["L_k"]


def required_classes(d):
    """Gamma, the leakage classes required for the deployment."""
    g = {"T"}
    if d["A"] in ("A2", "A3"):
        g.add("D")
        if d["S"] == "S2":
            g.add("P")
        if d.get("fault"):
            g.add("F")
    return g


def applicable_attacks(model, d):
    """Catalog attacks within the capabilities of the attacker of d.

    A known-technique attacker (S1) runs attacks without profiling and
    attacks whose templates come from the target itself, whereas profiling
    on a clone with known keys, masks, or messages requires a profiling
    attacker (S2).
    """
    ops = {d["operation"]}
    if d.get("keygen_on_device"):
        ops.add("keygen")
    out = []
    for a in model.attacks:
        if a["operation"] not in ops:
            continue
        if a["channel"] == "timing":
            out.append(a)
            continue
        if d["A"] == "A1":
            continue
        if a["channel"] == "fault" and not d.get("fault"):
            continue
        if a["profiling"] == "clone" and d["S"] != "S2":
            continue
        if a.get("chosen_inputs") and not d.get("chosen_inputs"):
            continue
        out.append(a)
    return out


def defeats(a, cand, n_k, margin):
    """True if attack a breaks candidate cand within the exposure n_k.

    An attack breaks a masked stack when the masking order of the stack
    does not exceed the order broken at this cost in its source and when
    the attack is not stopped by shuffling.  It also needs its traces or
    queries within reach under the safety margin, that is, margin * n_k >=
    traces.  A fault attack is met only by fault detection (L6), which
    includes control-flow checks, because one glitch can turn the shuffle
    into the identity permutation.  Without L6 a fault attack defeats every
    masking order, which is a worst case beyond the first order shown by
    Jendral et al.
    """
    if a["channel"] == "timing":
        return False                 # L1 is always present and checked by E1
    if a["channel"] == "fault":
        return not cand.l6
    if a["operation"] == "keygen":
        return True                  # no catalog entry masks key generation
    if cand.order > a["max_order"]:
        return False
    # Shuffling counts only on masked code.
    if cand.l3 and cand.order >= 1 and not a.get("bypasses_shuffling", False):
        return False
    return margin * n_k >= a["traces"]


# Structural rule for class P.  The catalog lists only attacks with published
# key-recovery costs on ML-KEM and ML-DSA, whereas single-trace profiled
# attacks on related lattice schemes are left out.  A profiling attacker is
# therefore met by masking with shuffling or by masking of order 2 or more,
# pending the profiled evaluation E4.
CLASS_P_RULE = {"id": "classP_rule", "channel": "power",
                "note": "class P needs masking with shuffling or order >= 2"}


def baseline_blockers(cand, d):
    if "P" in required_classes(d):
        if cand.order < 1 or (cand.order == 1 and not cand.l3):
            return [CLASS_P_RULE]
    return []


def coverage(model, cand, d, attacks=None):
    """(covered, blockers) for a candidate against the applicable attacks."""
    if attacks is None:
        attacks = applicable_attacks(model, d)
    n_k = exposure(d)
    margin = d.get("margin", 10)
    blockers = baseline_blockers(cand, d)
    blockers += [a for a in attacks if defeats(a, cand, n_k, margin)]
    return not blockers, blockers


def evidence(cand, d, attacks=None):
    """Evidence level required for the selected stack.

    E1 covers the binary-level constant-time check, whereas a first-order
    masked stack facing a proximate attacker needs E2.  E3 applies when
    coverage rests on a masking order of 2 or more or on shuffling that
    blocks a cataloged non-profiled attack, because only higher-order and
    targeted tests can confirm such claims.  A profiling attacker requires
    E4, and fault capability or a high-value deployment requires E5.
    """
    if attacks is None:
        attacks = []
    g = required_classes(d)
    level = 1
    if "D" in g and cand.order >= 1:
        level = max(level, 2 if cand.order == 1 else 3)
    if "D" in g and cand.l3 and cand.order >= 1:
        for a in attacks:
            if (a["channel"] == "power" and a["profiling"] != "clone"
                    and a["operation"] == d["operation"]
                    and cand.order <= a["max_order"]
                    and not a.get("bypasses_shuffling", False)):
                level = max(level, 3)
    if "P" in g:
        level = max(level, 4)
    if "F" in g or d.get("high_value"):
        level = 5
    return EVIDENCE[level]


# ---------------------------------------------------------------------------
# Selection (Algorithm 1)
# ---------------------------------------------------------------------------

def implementations_for(model, d):
    out = []
    for impl in model.impls.values():
        if impl["operation"] != d["operation"]:
            continue
        if d.get("fips204") and not impl.get("fips204", True):
            continue
        out.append(impl)
    return out


def layer_options(d):
    """(l3, l6) options for the optional coverage layers."""
    l6 = (False, True) if "F" in required_classes(d) else (False,)
    return [(l3, f) for l3 in (False, True) for f in l6]


def all_candidates(model, d):
    """Every stack, for the exhaustive search of the self-test."""
    l2 = bool(d.get("insurance_l2"))
    return [Candidate(impl, l2, l3, l6)
            for impl in implementations_for(model, d)
            for l3, l6 in layer_options(d)]


def minimal_candidates(model, d, attacks):
    """Inclusion-minimal covering stacks (Proposition 1).

    Adding a layer never lowers a cost and never removes coverage.  A stack
    with a layer not needed for its coverage is therefore never better than
    the same stack without that layer, so only minimal covers are evaluated.
    An implementation without any covering option is returned once with all
    optional layers, so that its blockers can be reported.
    """
    l2 = bool(d.get("insurance_l2"))
    out = []
    for impl in implementations_for(model, d):
        opts = layer_options(d)
        cov = [o for o in opts
               if coverage(model, Candidate(impl, l2, *o), d, attacks)[0]]
        if not cov:
            out.append((Candidate(impl, l2, *opts[-1]), False))
            continue
        for o in cov:
            if not any(q != o and q[0] <= o[0] and q[1] <= o[1] for q in cov):
                out.append((Candidate(impl, l2, *o), True))
    return out


def select(model, d, exhaustive=False):
    """Run Algorithm 1 and return (best row or None, all rows)."""
    attacks = applicable_attacks(model, d)
    if exhaustive:
        pairs = [(c, None) for c in all_candidates(model, d)]
    else:
        pairs = minimal_candidates(model, d, attacks)
    rows = []
    for cand, known in pairs:
        covered, blockers = coverage(model, cand, d, attacks)
        r = evaluate(model, cand, d)
        r["covered"] = covered
        r["blockers"] = blockers
        r["evidence"] = evidence(cand, d, attacks)
        rows.append(r)
    ok = [r for r in rows if r["covered"] and r["feasible"]]
    best = min(ok, key=lambda r: r["J"]) if ok else None
    return best, rows


def binding(rows):
    """Name why no stack survives, either coverage or the failed tests."""
    covered = [r for r in rows if r["covered"]]
    if not covered:
        return "coverage"
    closest = min(covered, key=lambda r: r["J"])
    return ",".join(k for k, v in closest["tests"].items() if not v)


def decision(model, d, outcome=False):
    """Short decision label used by the robustness analysis and the tests.

    With outcome=True the label keeps only the layers and the masking order,
    so it ignores the winner among several equivalent implementations.
    """
    best, rows = select(model, d)
    if best is None:
        return "ESCALATE(" + binding(rows) + ")"
    if outcome:
        return "+".join(best["cand"].layers()) + " order %d" % best["cand"].order
    return best["cand"].name


# ---------------------------------------------------------------------------
# Escalation (descriptor changes, then a rerun)
# ---------------------------------------------------------------------------

def rekey_limit(model, d):
    """Largest exposure N_k that lets some software stack cover d.

    Returns (n_max, candidate name), or None when exposure limits cannot
    help because a single-trace or key-generation attack is binding.  Like
    ephemeral keys, the new keys come from key generation on the device, so
    re-keying is ruled out by a key-generation attack within reach of the
    attacker.  Among stacks with the same limit, the stack with the lowest
    J(s) is reported, which is the stack picked by the selection under that
    exposure.
    """
    d = dict(d, keygen_on_device=True)
    attacks = applicable_attacks(model, d)
    margin = d.get("margin", 10)
    best = None
    for impl in implementations_for(model, d):
        for l3, l6 in layer_options(d):
            cand = Candidate(impl, bool(d.get("insurance_l2")), l3, l6)
            if baseline_blockers(cand, d):
                continue
            limits = []
            for a in attacks:
                if not defeats(a, cand, float("inf"), margin):
                    continue
                if a["operation"] == "keygen" or a["channel"] == "fault":
                    limits = None
                    break
                limits.append(a["traces"] / margin)
            if limits is None:
                continue
            n_max = min(limits) if limits else float("inf")
            r = evaluate(model, cand, d)
            if not r["feasible"]:
                continue
            if (best is None or n_max > best[0]
                    or (n_max == best[0] and r["J"] < best[2])):
                best = (n_max, cand.name, r["J"])
    return None if best is None else best[:2]


def rekey_period(model, d):
    """(n_max, period in seconds, stack name) of the re-keying design, or None."""
    rk = rekey_limit(model, d)
    if rk is None or rk[0] == float("inf") or d.get("key_usage") == "ephemeral":
        return None
    return rk[0], rk[0] / d["R_o"], rk[1]


def period_label(seconds):
    """Period bound rounded down, in days, in hours, or in minutes."""
    if seconds >= 86400:
        return "below %.2f days" % (math.floor(seconds / 864) / 100)
    if seconds >= 3600:
        return "below %.1f hours" % (math.floor(seconds / 360) / 10)
    return "below %.0f minutes" % math.floor(seconds / 60)


def escalation_changes(d):
    """Descriptor changes tried by the escalation step, as (label, changes).

    Authenticated ciphertexts remove the chosen-ciphertext flag, but the
    device then verifies the ML-DSA-65 signature of every ciphertext before
    its decapsulation, twice when the attacker can inject faults.
    """
    out = []
    if d["operation"] == "decaps" and d.get("key_usage") != "ephemeral":
        out.append(("ephemeral keys",
                    {"key_usage": "ephemeral", "keygen_on_device": True}))
    if d.get("chosen_inputs"):
        out.append(("authenticated ciphertexts",
                    {"chosen_inputs": False, "verify": "mldsa65_verify"}))
    if d.get("rng") == "on_demand":
        out.append(("idle-time randomness pool", {"rng": "pool"}))
    if d.get("B_c_offpath"):
        out.append(("off-path budget (session resumption)",
                    {"B_c": d["B_c_offpath"]}))
    return out


def escalation_options(model, d):
    """Rerun the selection under each escalation design of the paper."""
    opts = []
    for label, changes in escalation_changes(d):
        d2 = dict(d)
        d2.update(changes)
        opts.append((label, decision(model, d2)))
    rk = rekey_period(model, d)
    if rk is not None:
        n_max, period, name = rk
        if n_max < 1:
            opts.append(("re-keying with N_k < %.1f" % n_max,
                         "impossible, because one operation per key is "
                         "already within reach of an attack"))
        else:
            label = "re-keying with N_k < %.0f (period %s)" % (
                n_max, period_label(period))
            if period >= d.get("min_rekey_period", 86400):
                opts.append((label, name))
            else:
                opts.append((label,
                             "impractical, because the period is below one day"))
    opts.append(("relocate the secret or use a certified secure element",
                 "hardware path, evidence E5"))
    return opts


def designs(model, d):
    """Every escalation design of d with its selected row, if any.

    Returns a list of (label, descriptor, best row or None, binding).  The
    re-keying design keeps the exposure just below its limit.
    """
    out = []
    for label, changes in escalation_changes(d):
        d2 = dict(d)
        d2.update(changes)
        best, rows = select(model, d2)
        out.append((label, d2, best, None if best else binding(rows)))
    rk = rekey_period(model, d)
    if rk is not None and rk[1] >= d.get("min_rekey_period", 86400):
        d2 = dict(d)
        d2["L_k"] = rk[0] / d["R_o"] * (1 - 1e-9)
        best, rows = select(model, d2)
        out.append(("re-keying, period " + period_label(rk[1]), d2, best,
                    None if best else binding(rows)))
    return out


# ---------------------------------------------------------------------------
# Robustness over the prior ranges and over the attack assumptions
# ---------------------------------------------------------------------------

def robustness(catalog, d, outcome=False):
    """Decision at every corner of the prior box and the deciding priors.

    Returns (nominal decision, corners, changed corners, deciding priors).
    A prior is deciding when it changes the decision on its own at an end
    of its range.  With outcome=True, a change counts only if it alters the
    layers, the masking order, or the escalation.
    """
    ranges = prior_ranges(catalog)
    base = decision(Model(catalog), d, outcome)
    changed = 0
    corners = 0
    for ends in itertools.product((0, 1), repeat=len(ranges)):
        over = {name: (lo, hi)[e] for (name, lo, hi), e in zip(ranges, ends)}
        corners += 1
        if decision(Model(catalog, over), d, outcome) != base:
            changed += 1
    deciding = []
    for name, lo, hi in ranges:
        for v in (lo, hi):
            if decision(Model(catalog, {name: v}), d, outcome) != base:
                deciding.append(name)
                break
    return base, corners, changed, deciding


# Attack properties not shown in a source are marked in the catalog.
# "transfer" marks an attack shown on one algorithm of a step, "bypass" an
# attack whose source did not evaluate shuffling, and "stop" an attack whose
# source only recommends shuffling against it.
ASSUMPTIONS = ("transfer", "bypass", "stop")


def relax(catalog, kinds):
    """Copy of the catalog without the attack assumptions in kinds.

    Without "transfer", attacks shown on one algorithm of a step are
    dropped, because no cataloged implementation uses that algorithm.
    Without "bypass", shuffling stops the attacks whose sources did not
    evaluate it, whereas without "stop" it no longer stops the attacks whose
    sources only recommend it.
    """
    cat = copy.deepcopy(catalog)
    kept = []
    for a in cat["attacks"]:
        assumed = a.get("assumed", [])
        if "transfer" in kinds and "transfer" in assumed:
            continue
        if "bypass" in kinds and "bypass" in assumed:
            a["bypasses_shuffling"] = False
        if "stop" in kinds and "stop" in assumed:
            a["bypasses_shuffling"] = True
        kept.append(a)
    cat["attacks"] = kept
    return cat


def attack_sensitivity(catalog, d):
    """Outcome of d under each relaxed attack assumption and margin."""
    out = {"nominal": decision(Model(catalog), d, True)}
    for kinds in (("transfer",), ("bypass",), ("transfer", "bypass"), ("stop",)):
        out["without " + "+".join(kinds)] = decision(
            Model(relax(catalog, kinds)), d, True)
    for mu in (0.1, 1, 100, 1000):
        d2 = dict(d)
        d2["margin"] = mu
        out["margin %g" % mu] = decision(Model(catalog), d2, True)
    return out


# ---------------------------------------------------------------------------
# Design-space map, scalability benchmark, and selection time
# ---------------------------------------------------------------------------

def design_lines(model):
    """Cheapest decapsulation stack of every masking order, as in Fig. 1.

    The first-order stack carries shuffling, because first-order masking
    without shuffling falls to cataloged attacks.  The other orders carry no
    optional layer.  Returns a list of (candidate, cycles, random bytes).
    """
    best = {}
    for impl in model.impls.values():
        if impl["operation"] != "decaps":
            continue
        cand = Candidate(impl, l3=(impl["order"] == 1))
        cycles, _, rand, _ = costs(model, cand)
        if impl["order"] not in best or cycles < best[impl["order"]][1]:
            best[impl["order"]] = (cand, cycles, rand)
    return [best[k] for k in sorted(best)]


def map_clocks(points=201, deployments=()):
    """Clock grid of the map in MHz, from 16 to 480 MHz plus the deployments."""
    grid = [16 * (480 / 16) ** (i / (points - 1)) for i in range(points)]
    extra = [d["clock_hz"] / 1e6 for d in deployments if d["operation"] == "decaps"]
    return sorted(set(grid + extra))


def sweep(model, path, deployments=(), b_r=64 * 1024):
    """Write the data of the design-space map (Fig. 1) as CSV.

    For each line of design_lines() and each clock, the CSV holds the
    smallest latency budget with a fast TRNG and with on-demand randomness
    at b_r bytes per second.
    """
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("stack,order,clock_mhz,latency_trng_ms,latency_on_demand_ms\n")
        for cand, cycles, rand in design_lines(model):
            for f in map_clocks(deployments=deployments):
                t = cycles / (f * 1e6)
                fh.write("%s,%d,%.3f,%.4f,%.4f\n" % (
                    cand.name, cand.order, f, t * 1e3, (t + rand / b_r) * 1e3))
    return path


def bench(seed_count=10):
    """Exhaustive versus pruned search on synthetic catalogs (Section V-C).

    A synthetic catalog has L layers with n options each, and every option
    multiplies the cycles by a factor, adds memory and randomness, and covers
    a random subset of classes.  Costs and coverage are monotone, so the
    pruned search over inclusion-minimal covers must find the same optimum.
    Returns one row per configuration with the largest pruned count over
    the seeds and the number of catalogs without any covering stack.
    """
    classes = ["T", "D", "P", "F"]
    d = {"base_cycles": 707827, "f": 100e6, "B_c": 0.1, "B_m": 32768,
         "B_r": 102400, "R_o": 4 / 3600, "gamma": {"T", "D", "P"}}

    def make(L, n, seed):
        rng = random.Random(seed)
        cat = []
        for _ in range(L):
            covers = frozenset(rng.sample(classes, rng.randint(1, 2)))
            impls = [(1.0 + rng.random() * 3.0, rng.randint(0, 8192),
                      rng.randint(0, 4096)) for _ in range(n)]
            cat.append((covers, impls))
        return cat

    def ev(choice, cat):
        cyc, mem, rnd, cov = d["base_cycles"], 0, 0, set()
        for layer, opt in enumerate(choice):
            if opt is None:
                continue
            covers, impls = cat[layer]
            cf, m, r = impls[opt]
            cyc *= cf
            mem += m
            rnd += r
            cov |= covers
        lat = cyc / d["f"]
        ok = (d["gamma"] <= cov and lat <= d["B_c"] and mem <= d["B_m"]
              and rnd * d["R_o"] <= d["B_r"])
        J = (0.5 * lat / d["B_c"] + 0.25 * mem / d["B_m"]
             + 0.25 * rnd * d["R_o"] / d["B_r"])
        return ok, J

    def exhaustive(cat):
        best, count = None, 0
        for choice in itertools.product(
                *[[None] + list(range(len(i))) for _, i in cat]):
            count += 1
            ok, J = ev(choice, cat)
            if ok and (best is None or J < best):
                best = J
        return best, count

    def pruned(cat):
        L = len(cat)
        covers = []
        for k in range(1, L + 1):
            for sub in itertools.combinations(range(L), k):
                cov = set().union(*[cat[i][0] for i in sub])
                if d["gamma"] <= cov and not any(set(c) <= set(sub)
                                                 for c in covers):
                    covers.append(sub)
        best, count = None, 0
        for sub in covers:
            for picks in itertools.product(*[range(len(cat[i][1]))
                                             for i in sub]):
                choice = [None] * L
                for i, pk in zip(sub, picks):
                    choice[i] = pk
                count += 1
                ok, J = ev(choice, cat)
                if ok and (best is None or J < best):
                    best = J
        return best, count

    rows = []
    for L, n in [(5, 3), (5, 5), (6, 5), (6, 8), (7, 5), (8, 4)]:
        te = tp = 0.0
        agree = True
        cp_max = 0
        uncovered = 0
        for seed in range(seed_count):
            cat = make(L, n, seed)
            t0 = time.perf_counter()
            be, ce = exhaustive(cat)
            t1 = time.perf_counter()
            bp, cp = pruned(cat)
            t2 = time.perf_counter()
            te += t1 - t0
            tp += t2 - t1
            cp_max = max(cp_max, cp)
            if be is None:
                uncovered += 1
            agree = agree and ((be is None and bp is None) or
                               (be is not None and bp is not None
                                and abs(be - bp) < 1e-12))
        rows.append((L, n, ce, te / seed_count, cp_max, tp / seed_count,
                     agree, uncovered))
    return rows


def deployment_timing(model, deployments, runs=200):
    """Mean time of one selection and of one selection with all its designs.

    Returns {name: (select seconds, select plus designs seconds)}.
    """
    out = {}
    for d in deployments:
        t0 = time.perf_counter()
        for _ in range(runs):
            select(model, d)
        t1 = time.perf_counter()
        for _ in range(runs):
            select(model, d)
            designs(model, d)
        t2 = time.perf_counter()
        out[d["name"]] = ((t1 - t0) / runs, (t2 - t1) / runs)
    return out


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def share(x, budget):
    return "%.0f%%" % (100 * x / budget)


def row_text(r, d):
    """One line with the latency and its parts, the memory, the rate, and J."""
    parts = "cyc %.1f" % (r["t_cyc"] * 1e3)
    if r["t_ver"]:
        parts += " + ver %.1f" % (r["t_ver"] * 1e3)
    if r["t_rand"]:
        parts += " + rnd %.1f" % (r["t_rand"] * 1e3)
    return "lat %.1f ms (%s, %s) RAM %.0f B (%s) rnd %.1f B/s J %.3f %s" % (
        r["latency"] * 1e3, share(r["latency"], d["B_c"]), parts, r["stack"],
        share(r["stack"], d["B_m"]), r["rate"], r["J"], r["evidence"])


def report(model, d):
    best, rows = select(model, d)
    g = required_classes(d)
    n_k = exposure(d)
    attacks = applicable_attacks(model, d)
    print("Deployment: %s" % d.get("label", d.get("name", "descriptor")))
    print("Required coverage Gamma = %s, exposure N_k = %s per key epoch"
          % (sorted(g), "{:,.0f}".format(n_k)))
    if attacks:
        print("Applicable catalog attacks: "
              + ", ".join(a["id"] for a in attacks))
    hdr = "%-46s %9s %9s %9s %5s %7s  %s" % (
        "stack", "lat[ms]", "RAM[B]", "rnd[B/s]", "feas", "J", "evidence")
    print(hdr)
    print("-" * len(hdr))
    for r in sorted(rows, key=lambda r: (not (r["covered"] and r["feasible"]),
                                          r["J"])):
        note = []
        if not r["covered"]:
            note.append("blocked by " + ",".join(a["id"] for a in r["blockers"]))
        fails = [k for k, v in r["tests"].items() if not v]
        if fails:
            note.append("violates " + ",".join(fails))
        if r["priors_used"]:
            note.append("prior: " + ",".join(r["priors_used"]))
        ok = r["covered"] and r["feasible"]
        print("%-46s %9.1f %9.0f %9.1f %5s %7.3f  %s  %s" % (
            r["cand"].name, r["latency"] * 1e3, r["stack"], r["rate"],
            "yes" if ok else "NO", r["J"], r["evidence"], "; ".join(note)))
    if best is not None:
        print("Selected: %s, %s" % (best["cand"].name, row_text(best, d)))
    else:
        print("No stack survives (binding: %s)." % binding(rows))
        covered = [r for r in rows if r["covered"]]
        if covered:
            closest = min(covered, key=lambda r: r["J"])
            fastest = min(covered, key=lambda r: r["latency"])
            print("  closest by J: %s, %s" % (closest["cand"].name,
                                              row_text(closest, d)))
            print("  fastest:      %s, %s" % (fastest["cand"].name,
                                              row_text(fastest, d)))
        print("Designs after escalation:")
        for label, d2, b2, bind in designs(model, d):
            if b2 is None:
                print("  - %-44s -> ESCALATE(%s)" % (label, bind))
            else:
                print("  - %-44s -> %s, %s" % (label, b2["cand"].name,
                                               row_text(b2, d2)))
        for label, dec in escalation_options(model, d):
            if label.startswith("re-keying") and dec.startswith(
                    ("impractical", "impossible")):
                print("  - %-44s -> %s" % (label, dec))
        print("  - %-44s -> hardware path, evidence E5"
              % "certified secure element or key relocation")
    print()
    return best, rows


def summary(model, deployments):
    print("%-22s %-10s %-44s %-8s %s" % ("deployment", "Gamma", "decision",
                                           "evidence", "binding"))
    for d in deployments:
        best, rows = select(model, d)
        g = "".join(sorted(required_classes(d)))
        if best is None:
            print("%-22s %-10s %-44s %-8s %s" % (d["name"], g, "ESCALATE",
                                                   "-", binding(rows)))
        else:
            print("%-22s %-10s %-44s %-8s %s" % (
                d["name"], g, best["cand"].name, best["evidence"],
                "lat %s, RAM %s" % (share(best["latency"], d["B_c"]),
                                    share(best["stack"], d["B_m"]))))


# ---------------------------------------------------------------------------
# Self-test against the numbers quoted in the paper
# ---------------------------------------------------------------------------

def run_checks(catalog, deployments):
    ok = True

    def check(label, cond):
        nonlocal ok
        print(("PASS" if cond else "FAIL") + "  " + label)
        ok = ok and bool(cond)

    model = Model(catalog)
    impls = model.impls
    by_name = {d["name"]: d for d in deployments}
    check("pqm4 ML-KEM-768 decapsulation stack is 6,452 B",
          impls["pqm4_m4fspeed"]["stack_bytes"] == 6452)
    check("masked Kyber768 decapsulation at 2 shares needs 12,132 B",
          impls["bc_o1"]["stack_bytes"] == 12132)
    check("masked Dilithium3 signing at 2 shares needs 145,532 B",
          impls["azouaoui_det"]["stack_bytes"] == 145532)
    det = costs(model, Candidate(impls["azouaoui_det"]))[0] / 100e6
    rnd = costs(model, Candidate(impls["azouaoui_rand"]))[0] / 100e6
    det3 = costs(model, Candidate(impls["azouaoui_det"], l3=True))[0] / 100e6
    rnd3 = costs(model, Candidate(impls["azouaoui_rand"], l3=True))[0] / 100e6
    check("masked FIPS 204 signing needs about 1.09 s at 100 MHz",
          1.085 < det < 1.10)
    check("the randomized variant needs about 0.61 s at 100 MHz",
          0.605 < rnd < 0.62)
    check("with shuffling, masked FIPS 204 signing needs about 1.37 s",
          1.36 < det3 < 1.37)
    check("with shuffling, the randomized variant needs about 0.77 s",
          0.76 < rnd3 < 0.77)
    for d in deployments:
        b1, _ = select(model, d)
        b2, _ = select(model, d, exhaustive=True)
        same = ((b1 is None and b2 is None) or
                (b1 is not None and b2 is not None
                 and abs(b1["J"] - b2["J"]) < 1e-12))
        check("%s: pruned search equals exhaustive search" % d["name"], same)
    for d in deployments:
        if "expect" in d:
            check("%s: decision %s" % (d["name"], d["expect"]),
                  decision(model, d) == d["expect"])
        changes = dict(escalation_changes(d))
        for label, want in d.get("expect_designs", {}).items():
            d2 = dict(d)
            d2.update(changes[label])
            check("%s with %s: %s" % (d["name"], label, want),
                  decision(model, d2, outcome=True) == want)
        for label, want in d.get("expect_rekey", {}).items():
            rk = rekey_period(model, d)
            got = None if rk is None else (period_label(rk[1]), rk[2])
            check("%s re-keying %s: %s" % (d["name"], label, want),
                  got is not None and got[0] == label and got[1] == want)
        if d.get("expect_no_rekey"):
            rk = rekey_period(model, d)
            check("%s: re-keying cannot cover the deployment" % d["name"],
                  rk is None or rk[1] < d.get("min_rekey_period", 86400))
    relay = dict(by_name["relay"])
    relay.update(dict(escalation_changes(relay))["authenticated ciphertexts"])
    fastest = min(evaluate(model, c, relay)["latency"]
                  for c, covered in minimal_candidates(
                      model, relay, applicable_attacks(model, relay))
                  if covered)
    check("relay with authenticated ciphertexts still needs about 141.8 ms",
          0.1413 < fastest < 0.1423)
    sens = attack_sensitivity(catalog, by_name["smart_meter"])
    check("meter fits with first-order masking without the transfer assumption",
          sens["without transfer"] == "L1+L3+L4+L5 order 1")
    check("meter fits with first-order masking when shuffling stops all attacks",
          sens["without bypass"] == "L1+L3+L4+L5 order 1")
    sens = attack_sensitivity(catalog, by_name["grid"])
    check("grid escalates on latency when shuffling stops all attacks",
          sens["without bypass"] == "ESCALATE(latency)")
    sens = attack_sensitivity(catalog, by_name["signer"])
    check("signer escalates on coverage when shuffling stops no attack",
          sens["without stop"] == "ESCALATE(coverage)")
    rows = bench(seed_count=1)
    check("synthetic catalogs: pruned search finds the exhaustive optimum",
          all(r[6] for r in rows))
    print("\nAll checks passed." if ok else "\nSOME CHECKS FAILED.")
    return 0 if ok else 1


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--deployment", metavar="NAME")
    g.add_argument("--all", action="store_true")
    g.add_argument("--descriptor", metavar="FILE")
    g.add_argument("--robustness", action="store_true")
    g.add_argument("--assumptions", action="store_true")
    g.add_argument("--sweep", metavar="CSV")
    g.add_argument("--bench", action="store_true")
    g.add_argument("--check", action="store_true")
    args = ap.parse_args()

    catalog = load_json("catalog.json")
    deployments = load_json("deployments.json")["deployments"]
    model = Model(catalog)
    by_name = {d["name"]: d for d in deployments}

    if args.check:
        sys.exit(run_checks(catalog, deployments))
    if args.deployment:
        report(model, by_name[args.deployment])
    elif args.all:
        for d in deployments:
            report(model, d)
        summary(model, deployments)
    elif args.descriptor:
        with open(args.descriptor, encoding="utf-8") as fh:
            report(model, json.load(fh))
    elif args.robustness:
        print("%-46s %-30s %-7s %-7s %s" % (
            "deployment / design", "decision", "outcome", "winner",
            "deciding priors (outcome | winner)"))
        for d in deployments:
            options = [("as given", {})] + escalation_changes(d)
            for label, changes in options:
                d2 = dict(d)
                d2.update(changes)
                base, corners, ch_w, dec_w = robustness(catalog, d2)
                _, _, ch_o, dec_o = robustness(catalog, d2, outcome=True)
                print("%-46s %-30s %-7s %-7s %s | %s" % (
                    d["name"] + " / " + label, base.replace("L1+", ""),
                    "%d/%d" % (ch_o, corners), "%d/%d" % (ch_w, corners),
                    ",".join(dec_o) or "-", ",".join(dec_w) or "-"))
    elif args.assumptions:
        for d in deployments:
            options = [("as given", {})] + escalation_changes(d)
            for label, changes in options:
                d2 = dict(d)
                d2.update(changes)
                sens = attack_sensitivity(catalog, d2)
                base = sens.pop("nominal")
                diff = ["%s: %s" % (k, v) for k, v in sens.items() if v != base]
                print("%-46s %-24s %s" % (d["name"] + " / " + label,
                                          base.replace("L1+", ""),
                                          "; ".join(diff) or "unchanged"))
    elif args.sweep:
        print("wrote", sweep(model, args.sweep, deployments))
    elif args.bench:
        print("%2s %3s %11s %9s %8s %9s %5s %s" % (
            "L", "n", "exhaustive", "t_exh[s]", "pruned", "t_pru[s]", "same",
            "uncovered"))
        for L, n, ce, te, cp, tp, same, unc in bench():
            print("%2d %3d %11s %9.3f %8s %9.4f %5s %d" % (
                L, n, "{:,}".format(ce), te, "{:,}".format(cp), tp, same, unc))
        print("\nselection time per deployment (mean of 200 runs)")
        for name, (t_sel, t_all) in deployment_timing(model, deployments).items():
            print("  %-12s %.3f ms, with its designs %.3f ms"
                  % (name, t_sel * 1e3, t_all * 1e3))


if __name__ == "__main__":
    main()
