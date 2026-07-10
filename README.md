# Countermeasure-Stack Selection Artifact

Reference implementation of the constraint-based selection framework from
*"Selecting Lightweight Side-Channel Countermeasures for Embedded
Post-Quantum Cryptography: A Constraint-Based Framework"*.

`select.py` evaluates a deployment descriptor `D = (A, S, f, L_k, R_o, B_c, B_m, B_r)`
(with `f` the operating clock, alongside the randomness-delivery mode and ranking
weights) against the paper's Table I cost priors (published Cortex-M measurements),
applies the Section IV-B coverage and resource-feasibility rules, ranks
feasible candidates by the normalized budget-utilization objective `J(s)`,
and reports the selected stack with its required evidence level.

Coverage follows Section II-C: a remote-only adversary (`A1`) induces
`{T}` regardless of sophistication, since power and EM channels require
proximate access. Supplying `L_k` (lifetime of the longest-lived on-device
secret, in seconds) activates the Section IV-A exposure advisory, which
reports `N_k = R_o * L_k`; adding `attack_traces_D` (the smallest published
class-D attack trace count for the chosen implementation) sizes the L5
re-keying epoch that keeps `N_k` an order of magnitude below that count.

Requires Python 3.8+ (standard library only).

```sh
python select.py --example grid       # Section V-A worked example
python select.py --example battery    # Section V-B worked example
python select.py --example signer     # Section V-C on-device ML-DSA signing
python select.py --descriptor d.json  # arbitrary descriptor
python select.py --check              # self-test against the paper's numbers
```

## Data provenance

All cycle, stack, and randomness figures are published measurements:

| Prior | Value | Source |
|---|---|---|
| Unprotected ML-KEM-768 decaps (m4fspeed) | 707,827 cycles; 6,452 B stack | pqm4 repository |
| Unprotected ML-KEM-768 decaps (m4fstack) | 714,194 cycles; 2,844 B stack | pqm4 repository |
| First-order masked decaps (Heinz et al.) | 2,978,441 cycles (RNG included) | ePrint 2022/058 |
| First-order masked decaps (Bos et al.) | 3,116,000 cycles; 12,072 random bytes | TCHES 2021(4), Table 2 |
| Second-order masked decaps (Bos et al.) | 44,347,000 cycles; 902,126 random bytes | TCHES 2021(4), Table 2 |
| Unprotected ML-DSA-65 signing | 3,224,000 cycles | pqm4, as quoted by Azouaoui et al. |
| First-order masked ML-DSA-65 signing, randomized | 14,282,000 cycles | TCHES 2023(4), Section 6.3 (STM32L4R5) |
| First-order masked ML-DSA-65 signing, deterministic | 24,005,000 cycles | TCHES 2023(4), Section 6.3 (STM32L4R5) |
| Unprotected ML-DSA-65 signing stack (m4fstack) | 6,616 B | pqm4 repository |

The pqm4 figures were read from `benchmarks.md` at commit `cc2c1b99`
(accessed July 2026).

None of the cited masked implementations reports RAM, so masked-RAM figures
are conservative structural priors (a multiplier on the measured unprotected
stack), clearly flagged in the output and pending the protected-implementation
benchmarking called for in Section VI of the paper. The L2/L3 layer factors
are coarse priors from the ranges reported in the literature (see Section III).
