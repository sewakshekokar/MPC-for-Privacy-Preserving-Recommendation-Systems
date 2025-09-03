# Secure User-Profile Update (Additive Secret Sharing + Beaver Triples)

This package contains Python scripts that implement and simulate the secure user-profile
update protocol described in the assignment. It uses additive secret sharing (mod 2^32)
and Beaver triples for secure multiplication. The simulation runs all three parties
(P0, P1, P2) inside a single Python process for clarity and debugging.

## Files

- `secure_update_mpc.py` : Main MPC simulator. Reads share CSVs and queries, runs secure inner-product and updates.
- `generate_shares.py`   : Generates random U, V matrices and splits them into additive shares (U0/U1, V0/V1), plus queries.
- `U0.csv`, `U1.csv`, `V0.csv`, `V1.csv`, `queries.csv` : sample files produced by `generate_shares.py`.

## How to run

1. Generate shares (example):
   ```bash
   python generate_shares.py --m 3 --n 5 --k 4 --q 2 --seed 42
   ```
   This writes `U0.csv`, `U1.csv`, `V0.csv`, `V1.csv`, and `queries.csv` in the current directory.

2. Run the secure update simulator:
   ```bash
   python secure_update_mpc.py --U0 U0.csv --U1 U1.csv --V0 V0.csv --V1 V1.csv --queries queries.csv --seed 42
   ```

   The script prints detailed debug output:
   - Shares for each party
   - Opened masked values (d = x-a, e = y-b)
   - Beaver triple shares per multiplication
   - Inner product shares and reconstruction
   - Delta (1 - inner) shares and reconstruction
   - Updated user vector shares and reconstruction

## Protocol summary (brief)

- **Additive secret sharing**: A secret `x` is split into random shares `x0, x1, x2` (for P0,P1,P2)
  such that `x = (x0 + x1 + x2) mod 2^32`. Each party stores only its share.

- **Beaver triples for multiplication**:
  - Pre-generate random `a, b`, and compute `c = a*b`.
  - Secret-share `(a,b,c)` among the parties.
  - To multiply `[x] * [y]`:
    1. Each party computes and reveals `d_i = x_i - a_i` and `e_i = y_i - b_i`. Parties reconstruct `d` and `e`.
    2. Each party computes local share `z_i = c_i + b_i*d + a_i*e`.
    3. One party adds the public `d*e` term to its share so that `z0+z1+z2 = x*y`.
  - Opening `d` and `e` leaks nothing about `x` and `y` because `a` and `b` are random.

- **Update step**:
  1. Securely compute `dot = <u, v>` (using per-element Beaver multiplications).
  2. Compute `delta = 1 - dot` as a shared value.
  3. For each feature coordinate, compute `v_coord * delta` securely (Beaver) and add to `u_coord` locally.

## Notes & Security

- The scripts here simulate the parties in one process for ease of testing and debugging.
  In an actual MPC deployment, parties run as separate processes/hosts and exchange messages
  to open the masked values (`d` and `e`) and to coordinate Beaver triple usage.
- The model assumed is **honest-but-curious** (semi-honest). The code does not implement
  active-malicious security measures like MACs or zero-knowledge proofs.
- Arithmetic is modulo 2^32 to emulate 32-bit integer wrap-around.
- The code prints reconstructed values for debugging — in a real secure run you would not
  reveal these to any single party.

## Example

1. Generate data:
   ```bash
   python generate_shares.py --m 3 --n 5 --k 4 --q 2
   ```

2. Run MPC:
   ```bash
   python secure_update_mpc.py --U0 U0.csv --U1 U1.csv --V0 V0.csv --V1 V1.csv --queries queries.csv
   ```

You should see printed traces showing how Beaver triples are used and how updates proceed.

## Contact / Attribution

This code is an educational simulation aligned with the CS670 A1 specification (IIT Kanpur).
Use it as a starting point for implementing the real multi-process/Dockerized version.
