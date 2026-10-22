# Countermeasure-Stack Selection Artifact

Reference implementation of the selection framework from
*"Selecting Side-Channel Countermeasures for Post-Quantum Cryptography on
Resource-Constrained Cyber-Physical Devices"*.

`select.py` checks every candidate countermeasure stack of a deployment against
a catalog of published attacks and against the latency, memory, and randomness
budgets of the device. The feasible stacks are ranked by normalized budget
utilization, and the selected stack is reported with its required evidence
level. When no stack survives, the script names the binding constraint and
reruns the selection under each escalation option of the paper.

Requires Python 3.8+ (standard library only).

```sh
python select.py --deployment smart_meter  # one deployment of the paper
python select.py --all                     # all deployments and a summary
python select.py --descriptor d.json       # arbitrary descriptor (JSON)
python select.py --robustness              # decisions over the prior ranges
python select.py --assumptions             # decisions under other attack assumptions
python select.py --sweep map.csv           # data of the design-space map (Fig. 1)
python select.py --bench                   # scalability on synthetic catalogs
python select.py --check                   # self-test against the paper
```

## Files

- `select.py` holds the model, the selection algorithm, and the analyses.
- `catalog.json` holds the implementation costs, the priors with their ranges,
  and the attack catalog. Every value names its source.
- `deployments.json` holds the six deployments of the paper together with the
  decisions expected by the self-test.

## How a decision is made

A descriptor states the attacker and the key usage together with the clock and
the budgets. The attacker has a physical access class A and a sophistication
S, plus flags for chosen inputs and fault capability. The exposure N_k counts
the secret-bearing operations per key epoch, so an ephemeral key gives
N_k = 1. A deployment with authenticated ciphertexts also pays one ML-DSA-65
signature check per decapsulation, so its latency includes the verification
cycles. The check runs twice when the attacker can inject faults, because one
glitch could skip a single check.

Most measured cycle counts include the time of an on-chip TRNG. The two counts
from the STM32F303 exclude it, since this board has no TRNG, so the latency
of these implementations always includes the generation time, as with
on-demand randomness. Ephemeral keys and re-keying both generate new keys on
the device, so a key-generation attack within reach of the attacker rules out
both designs.

An attack of the catalog applies when the attacker meets its requirements. A
known-technique attacker (S1) runs attacks without profiling and attacks whose
templates come from the target itself, whereas profiling on a clone with known
keys, masks, or messages needs S2. An applicable attack defeats a stack when the masking
order of the stack does not exceed the order broken in its source, when it is
not stopped by shuffling, and when its traces lie within reach. The safety
margin mu of the paper (default 10, the field `margin` of a descriptor) defines
this reach as mu * N_k >= traces. Shuffling only counts on masked stacks,
because improved attacks reduce its gain without masking. Profiling
attackers also face a structural rule, under which class P needs masking with
shuffling or masking of order 2 or more.

Each attack is assumed to transfer to every implementation of the same
operation up to the highest order broken in its source, because every such
implementation contains the attacked step. Adding a layer never lowers a cost
or removes coverage, so the search only evaluates inclusion-minimal covering
stacks. The self-test checks that this pruned search finds the same optimum as
the exhaustive search.

## Attack assumptions

Some attack properties are assumed rather than shown in their sources, so they
are marked in the field `assumed` of each attack.

- `transfer` marks an attack shown on one algorithm of a step, such as one
  masked comparison. The comparison attack of Hermelink et al. carries this
  mark, since its source even states that it does not directly apply to two
  earlier comparison designs.
- `bypass` marks an attack whose source did not evaluate shuffling, so the
  attack is assumed to pass it.
- `stop` marks an attack whose source only recommends shuffling against it, so
  shuffling is assumed to stop the attack. The attacks of Tosun et al. and of
  Zhao et al. (ACM CCS 2026) carry this mark. This choice is optimistic, since
  Zhao et al. show only that shuffling raises the trace count of their attack.

`--assumptions` reruns every decision and design without each kind of
assumption and with margins mu from 0.1 to 1000. The attack assumptions change
more outcomes than the cost priors of `--robustness`.

## Data provenance

Published figures come from pqm4 at commit `cc2c1b99` and from the papers named
in `catalog.json`. The per-pass signing counts of Azouaoui et al. come from
their Table 2, because the totals quoted in their Section 6.3 disagree with
that table. Three kinds of values come from our own QEMU measurements
(mps2-an386, Arm GNU Toolchain 11.3.Rel1).

| Value | 2 shares | 3 shares | 4 shares | Notes |
|---|---|---|---|---|
| Masked Kyber768 decapsulation stack | 12,132 B | 16,372 B | 20,476 B | pqm4_masked of Bronchain and Cassiers |
| Random bytes per masked decapsulation | 67,908 B | 197,552 B | 391,432 B | counted TRNG words times four |
| Masked Dilithium3 signing stack | 145,532 B | 181,076 B | 216,588 B | code of Azouaoui et al. in pqm4_masked |

The QEMU method reproduces every published pqm4 board figure of ML-KEM-768
and ML-DSA-65 within 24 bytes. Both speed baselines match exactly, with
6,452 B for ML-KEM-768 decapsulation and 68,872 B for ML-DSA-65 signing. Only
the measured numbers are part of this artifact, so no code of the measured
implementations is included.

Every prior without a measurement carries a range in `catalog.json`, and
`--robustness` reports which priors can change a decision inside these ranges.

## Reproducing the QEMU measurements

The measurements run on Linux (WSL works) with QEMU and the compiler of the
published pqm4 numbers, which is the Arm GNU Toolchain 11.3.Rel1.

```sh
sudo apt install qemu-system-arm make git python3 curl
T=arm-gnu-toolchain-11.3.rel1-x86_64-arm-none-eabi
curl -fsSLO https://developer.arm.com/-/media/Files/downloads/gnu/11.3.rel1/binrel/$T.tar.xz
echo "d420d87f68615d9163b99bbb62fe69e85132dc0a8cd69fca04e813597fe06121  $T.tar.xz" | sha256sum -c -
tar xf $T.tar.xz
git clone https://github.com/mupq/pqm4.git && git -C pqm4 checkout cc2c1b99
git -C pqm4 submodule update --init --recursive
git clone https://github.com/simple-crypto/pqm4_masked.git
git -C pqm4_masked submodule update --init --recursive
export PATH="$PWD/$T/bin:$PATH"
```

Two changes are needed for QEMU, and neither of them touches the measured
code.

- The pqm4 platform file `mk/mps2-an386.mk` passes the linker flag
  `--no-warn-rwx-segments`, which binutils 2.38 of this toolchain does not
  know. A copy of the file without this warning flag serves as the platform
  `mps2-an386-gcc11`.
- pqm4_masked reads the TRNG registers of the STM32. QEMU has no such
  peripheral, so a stand-in `libopencm3/stm32/rng.h` on the include path
  defines `RNG_SR`, `RNG_SR_DRDY`, and `RNG_DR`, and every read of `RNG_DR`
  returns the next word of a xorshift32 generator. The output quality of this
  generator does not matter for stack measurements, and the functional tests
  still pass.

```sh
cd pqm4
sed '/--no-warn-rwx-segments/d' mk/mps2-an386.mk > mk/mps2-an386-gcc11.mk
make PLATFORM=mps2-an386-gcc11 elf/crypto_kem_ml-kem-768_m4fspeed_stack.elf
qemu-system-arm -M mps2-an386 -nographic -semihosting \
    -kernel elf/crypto_kem_ml-kem-768_m4fspeed_stack.elf

cd ../pqm4_masked    # SHIM is the folder that holds libopencm3/stm32/rng.h
K=crypto_kem_kyber768_m4fspeed_masked
CFLAGS="-DNSHARES=2 -I$SHIM" make PLATFORM=mps2-an386 obj/.schemes.mk
CFLAGS="-DNSHARES=2 -I$SHIM" make PLATFORM=mps2-an386 elf/${K}_stack.elf
qemu-system-arm -M mps2-an386 -nographic -semihosting -kernel elf/${K}_stack.elf
```

Each stack benchmark prints the stack usage of every operation. The masked
builds repeat with `-DNSHARES=3` and `-DNSHARES=4` after `make clean`, and
`crypto_sign_dilithium3_m4f_masked_stack.elf` gives the signing figures. The
scheme list `obj/.schemes.mk` is generated first, because it is no longer
remade automatically by GNU make 4.4. The unmasked builds of pqm4_masked need a
dummy `-DNSHARES=1`, because a shared benchmark helper prints the share count.
The randomness counts come from `elf/${K}_speed_sub.elf` built with
`-DBENCH=1 -DBENCH_RND=1`, which counts 32-bit TRNG words, so the random bytes
are four times this count. The `tches` tag of pqm4_masked holds the release behind the
published cycle counts. The same steps on this tag give the 2-share
decapsulation stack of the table above (12,132 B), whereas the current branch
needs 12,148 B. Both versions agree on the 3-share stack and on the randomness
counts.
