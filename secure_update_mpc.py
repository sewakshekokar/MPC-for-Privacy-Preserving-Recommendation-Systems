#!/usr/bin/env python3
"""
secure_update_mpc.py

Simulates the secure user-profile update protocol (P0, P1, P2) using additive secret sharing
and Beaver triples. This is a single-process simulation that reads share files:
  - U0.csv, U1.csv (user shares for P0 and P1)
  - V0.csv, V1.csv (item shares for P0 and P1)
  - queries.csv (list of user,item index pairs)

Usage:
  python secure_update_mpc.py --U0 U0.csv --U1 U1.csv --V0 V0.csv --V1 V1.csv --queries queries.csv

All arithmetic is performed modulo 2^32 to simulate 32-bit wraparound. The script prints
debug logs showing shares, reconstructed values, Beaver triple data for multiplications,
and updated user vectors.
"""
import argparse
import csv
import random
from typing import List, Tuple

MOD = 2**32
MASK32 = MOD - 1

def addm(a: int, b: int) -> int:
    return (a + b) & MASK32

def subm(a: int, b: int) -> int:
    return (a - b) & MASK32

def mulm(a: int, b: int) -> int:
    return (a * b) & MASK32

def read_matrix_csv(filename: str) -> List[List[int]]:
    mat = []
    with open(filename, 'r', newline='') as f:
        reader = csv.reader(f)
        for row in reader:
            if not row:
                continue
            # allow whitespace, skip empty strings
            vals = [int(x) for x in row if x != ""]
            mat.append(vals)
    return mat

def read_queries_csv(filename: str) -> List[Tuple[int,int]]:
    queries = []
    with open(filename, 'r', newline='') as f:
        reader = csv.reader(f)
        header_skipped = False
        for row in reader:
            if not row:
                continue
            # Support files with or without header
            if not header_skipped:
                try:
                    int(row[0])
                except ValueError:
                    header_skipped = True
                    continue
                header_skipped = True
            queries.append((int(row[0]), int(row[1])))
    return queries

def gen_beaver_triple_shares() -> Tuple[Tuple[int,int,int], Tuple[int,int,int], Tuple[int,int,int]]:
    """
    Generate a Beaver triple (a,b,c=a*b) and return shares for P0,P1,P2 as tuples:
      a_shares = (a0,a1,a2), b_shares = (b0,b1,b2), c_shares = (c0,c1,c2)
    We simulate 3-party sharing for clarity; P2 typically provides randomness or triples.
    """
    a = random.randrange(MOD)
    b = random.randrange(MOD)
    c = mulm(a, b)
    a0 = random.randrange(MOD); a1 = random.randrange(MOD); a2 = (a - a0 - a1) % MOD
    b0 = random.randrange(MOD); b1 = random.randrange(MOD); b2 = (b - b0 - b1) % MOD
    c0 = random.randrange(MOD); c1 = random.randrange(MOD); c2 = (c - c0 - c1) % MOD
    return (a0,a1,a2), (b0,b1,b2), (c0,c1,c2)

def beaver_mul_three_party(
    x_shares: Tuple[int,int,int],
    y_shares: Tuple[int,int,int],
    a_shares: Tuple[int,int,int],
    b_shares: Tuple[int,int,int],
    c_shares: Tuple[int,int,int],
) -> Tuple[int,int,int]:
    """
    Simulate three-party Beaver multiplication.
    Input:
      x_shares = (x0,x1,x2), y_shares = (y0,y1,y2)
      (a_shares),(b_shares),(c_shares) as from gen_beaver_triple_shares.

    Protocol (simulated in-process):
      - Each party computes its local (xi - ai) and (yi - bi).
      - Parties open (reconstruct) d = x - a and e = y - b (we compute them directly).
      - Each party computes local share:
          zi = c_i + b_i * d + a_i * e
        Then add d*e to one designated party (we choose party 0) so sum(zi) = x*y.
    Returns:
      (z0, z1, z2) additive shares of the product.
    """
    x0, x1, x2 = x_shares
    y0, y1, y2 = y_shares
    a0, a1, a2 = a_shares
    b0, b1, b2 = b_shares
    c0, c1, c2 = c_shares

    # reconstruct x,y,a,b (publicly in simulation when opening differences)
    x = addm(addm(x0, x1), x2)
    y = addm(addm(y0, y1), y2)
    a = addm(addm(a0, a1), a2)
    b = addm(addm(b0, b1), b2)

    d = subm(x, a)
    e = subm(y, b)

    # each party computes its local share (without d*e)
    z0 = addm(c0, addm(mulm(b0, d), mulm(a0, e)))
    z1 = addm(c1, addm(mulm(b1, d), mulm(a1, e)))
    z2 = addm(c2, addm(mulm(b2, d), mulm(a2, e)))

    # assign public d*e to party 0 (consistent assignment)
    z0 = addm(z0, mulm(d, e))

    return z0, z1, z2

def reconstruct_three(shares: Tuple[int,int,int]) -> int:
    return addm(addm(shares[0], shares[1]), shares[2])

def secure_inner_product(
    u0: List[int], u1: List[int], u2: List[int],
    v0: List[int], v1: List[int], v2: List[int]
) -> Tuple[Tuple[int,int,int], int]:
    """
    Compute additive shares of <u,v> for three parties.
    Returns:
      (d0,d1,d2) shares and the reconstructed integer (for debugging).
    """
    assert len(u0) == len(u1) == len(u2) == len(v0) == len(v1) == len(v2)
    z0_sum = z1_sum = z2_sum = 0
    k = len(u0)
    for i in range(k):
        # per-element shares for x and y
        x_shares = (u0[i], u1[i], u2[i])
        y_shares = (v0[i], v1[i], v2[i])
        # generate a Beaver triple and its shares
        a_shares, b_shares, c_shares = gen_beaver_triple_shares()
        z0, z1, z2 = beaver_mul_three_party(x_shares, y_shares, a_shares, b_shares, c_shares)
        z0_sum = addm(z0_sum, z0)
        z1_sum = addm(z1_sum, z1)
        z2_sum = addm(z2_sum, z2)
        # debug print for this element
        # (printing a,b,c shares and opened d,e is helpful for trace)
        a_val = reconstruct_three(a_shares)
        b_val = reconstruct_three(b_shares)
        # open d,e for logs (safe because a,b random)
        x_val = reconstruct_three(x_shares)
        y_val = reconstruct_three(y_shares)
        d = subm(x_val, a_val)
        e = subm(y_val, b_val)
        print(f"    feature {i}: opened d={d}, e={e}; triple a={a_val}, b={b_val}")
        print(f"      product shares: P0={z0}, P1={z1}, P2={z2} (sum={(z0+z1+z2)%MOD}, expected={(x_val*y_val)%MOD})")
    d_shares = (z0_sum, z1_sum, z2_sum)
    reconstructed = reconstruct_three(d_shares)
    return d_shares, reconstructed

def secure_scalar_vector_mul_add(
    dst0: List[int], dst1: List[int], dst2: List[int],
    v0: List[int], v1: List[int], v2: List[int],
    s0: int, s1: int, s2: int
) -> Tuple[List[int], List[int], List[int]]:
    """
    Compute dst := dst + v * s where dst and v are vectors shared among P0,P1,P2 and
    s is a shared scalar (s0,s1,s2). All arithmetic modulo 2^32.
    Returns updated dst shares (dst0', dst1', dst2').
    """
    k = len(dst0)
    out0, out1, out2 = dst0[:], dst1[:], dst2[:]
    for i in range(k):
        x_shares = (v0[i], v1[i], v2[i])
        y_shares = (s0, s1, s2)
        a_shares, b_shares, c_shares = gen_beaver_triple_shares()
        z0, z1, z2 = beaver_mul_three_party(x_shares, y_shares, a_shares, b_shares, c_shares)
        out0[i] = addm(out0[i], z0)
        out1[i] = addm(out1[i], z1)
        out2[i] = addm(out2[i], z2)
    return out0, out1, out2

def secure_update_from_files(U0_file: str, U1_file: str, V0_file: str, V1_file: str, queries_file: str):
    U0 = read_matrix_csv(U0_file)
    U1 = read_matrix_csv(U1_file)
    V0 = read_matrix_csv(V0_file)
    V1 = read_matrix_csv(V1_file)
    queries = read_queries_csv(queries_file)

    # P2 shares are implicit zeros initially (in a real system P2 may hold nothing or its own shares)
    m = len(U0)
    k = len(U0[0]) if m>0 else 0
    U2 = [[0]*k for _ in range(m)]
    n = len(V0)
    kv = len(V0[0]) if n>0 else 0
    V2 = [[0]*kv for _ in range(n)]

    print(f"Loaded U0({len(U0)}x{k}), U1({len(U1)}x{k}), V0({len(V0)}x{kv}), V1({len(V1)}x{kv})")
    print(f"Processing {len(queries)} queries...")

    for qi, (ui, vj) in enumerate(queries, start=1):
        print(f"\n=== Query {qi}: user {ui}, item {vj} ===")
        u0 = U0[ui][:]
        u1 = U1[ui][:]
        u2 = U2[ui][:]
        v0 = V0[vj][:]
        v1 = V1[vj][:]
        v2 = V2[vj][:]

        print("  Shares of u: P0=", u0, " P1=", u1, " P2=", u2)
        print("  Shares of v: P0=", v0, " P1=", v1, " P2=", v2)

        # Reconstruct for debugging
        u_recon = [(u0[i] + u1[i] + u2[i]) % MOD for i in range(len(u0))]
        v_recon = [(v0[i] + v1[i] + v2[i]) % MOD for i in range(len(v0))]
        print("  Reconstructed u:", u_recon)
        print("  Reconstructed v:", v_recon)

        # Secure inner product
        d_shares, d_recon = secure_inner_product(u0, u1, u2, v0, v1, v2)
        print("  Inner-product shares: P0={}, P1={}, P2={}".format(d_shares[0], d_shares[1], d_shares[2]))
        print("  Reconstructed inner product:", d_recon)

        # Compute delta = 1 - inner  as shares
        # choose sharing: delta0 = 1 - d0, delta1 = -d1, delta2 = -d2  (mod MOD)
        delta0 = (1 - d_shares[0]) % MOD
        delta1 = (-d_shares[1]) % MOD
        delta2 = (-d_shares[2]) % MOD
        delta_recon = (delta0 + delta1 + delta2) % MOD
        print("  Delta shares: P0={}, P1={}, P2={}".format(delta0, delta1, delta2))
        print("  Reconstructed delta:", delta_recon)

        # Secure update: u := u + v * delta
        u0_new, u1_new, u2_new = secure_scalar_vector_mul_add(u0, u1, u2, v0, v1, v2, delta0, delta1, delta2)
        print("  Updated u shares P0={}, P1={}, P2={}".format(u0_new, u1_new, u2_new))
        u_recon_new = [(u0_new[i] + u1_new[i] + u2_new[i]) % MOD for i in range(len(u0_new))]
        print("  Reconstructed updated u:", u_recon_new)

        # store back updated shares
        U0[ui] = u0_new
        U1[ui] = u1_new
        U2[ui] = u2_new

def main():
    parser = argparse.ArgumentParser(description="Secure update MPC simulator (3-party, Python)")
    parser.add_argument("--U0", required=True, help="CSV file for U0 shares (P0)")
    parser.add_argument("--U1", required=True, help="CSV file for U1 shares (P1)")
    parser.add_argument("--V0", required=True, help="CSV file for V0 shares (P0)")
    parser.add_argument("--V1", required=True, help="CSV file for V1 shares (P1)")
    parser.add_argument("--queries", required=True, help="CSV file with queries (user_idx,item_idx)")
    parser.add_argument("--seed", type=int, default=42, help="PRNG seed (for reproducibility)")
    args = parser.parse_args()

    random.seed(args.seed)
    secure_update_from_files(args.U0, args.U1, args.V0, args.V1, args.queries)

if __name__ == "__main__":
    main()
