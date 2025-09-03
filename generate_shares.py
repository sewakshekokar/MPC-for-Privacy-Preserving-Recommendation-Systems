#!/usr/bin/env python3
"""
generate_shares.py

Generate random user and item latent vectors and split them into additive shares
for two parties (P0 and P1). Also generate a queries.csv file listing (user_idx, item_idx).

Usage:
  python generate_shares.py --m 3 --n 5 --k 4 --q 2

This will write:
  - U0.csv : P0's shares of U (m rows x k cols)
  - U1.csv : P1's shares of U
  - V0.csv : P0's shares of V (n rows x k cols)
  - V1.csv : P1's shares of V
  - queries.csv : q lines with user_idx,item_idx (with header)
"""
import argparse
import csv
import random

MOD = 2**32

def write_csv(filename, matrix):
    with open(filename, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerows(matrix)

def generate_shares(m: int, n: int, k: int, q: int, seed: int = 42):
    random.seed(seed)
    # underlying true matrices (for reference, not saved)
    U = [[random.randrange(MOD) for _ in range(k)] for _ in range(m)]
    V = [[random.randrange(MOD) for _ in range(k)] for _ in range(n)]

    # split into two shares (P0,P1) for each element
    U0 = [[0]*k for _ in range(m)]
    U1 = [[0]*k for _ in range(m)]
    V0 = [[0]*k for _ in range(n)]
    V1 = [[0]*k for _ in range(n)]

    for i in range(m):
        for j in range(k):
            s = random.randrange(MOD)
            U0[i][j] = s
            U1[i][j] = (U[i][j] - s) % MOD

    for i in range(n):
        for j in range(k):
            s = random.randrange(MOD)
            V0[i][j] = s
            V1[i][j] = (V[i][j] - s) % MOD

    # queries: randomly choose q pairs (user_idx, item_idx)
    queries = [(random.randrange(m), random.randrange(n)) for _ in range(q)]

    # write files
    write_csv("U0.csv", U0)
    write_csv("U1.csv", U1)
    write_csv("V0.csv", V0)
    write_csv("V1.csv", V1)

    with open("queries.csv", 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["user_idx", "item_idx"])
        for (u, v) in queries:
            writer.writerow([u, v])

    print("Wrote U0.csv, U1.csv, V0.csv, V1.csv, queries.csv")
    print(f"m={m}, n={n}, k={k}, q={q}, seed={seed}")

def main():
    parser = argparse.ArgumentParser(description="Generate secret shares for MPC assignment")
    parser.add_argument("--m", type=int, required=True, help="number of users (rows in U)")
    parser.add_argument("--n", type=int, required=True, help="number of items (rows in V)")
    parser.add_argument("--k", type=int, required=True, help="feature dimension (columns)")
    parser.add_argument("--q", type=int, required=True, help="number of queries")
    parser.add_argument("--seed", type=int, default=42, help="random seed")
    args = parser.parse_args()

    generate_shares(args.m, args.n, args.k, args.q, args.seed)

if __name__ == "__main__":
    main()
