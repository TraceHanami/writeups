import z3

def solve():
    with open("./interlock", "rb") as f:
        data = f.read()

    # Target vector at .rodata offset 0x2090 (16 bytes)
    target = data[0x2090:0x2090 + 16]
    # 16x16 matrix at .rodata offset 0x20a0 (256 bytes)
    matrix = [list(data[0x20a0 + i * 16 : 0x20a0 + (i + 1) * 16]) for i in range(16)]

    solver = z3.Solver()
    key = [z3.BitVec(f"k_{i}", 8) for i in range(16)]

    # Matrix multiplication modulo 256
    for i in range(16):
        expr = z3.BitVecVal(0, 8)
        for j in range(16):
            expr = expr + (z3.BitVecVal(matrix[i][j], 8) * key[j])
        solver.add(expr == target[i])

    if solver.check() == z3.sat:
        model = solver.model()
        solution = bytes([model[key[i]].as_long() for i in range(16)])
        print(f"[+] Key found: {solution.decode('latin1')}")
        return solution.decode('latin1')
    else:
        print("[-] No solution found.")
        return None

if __name__ == "__main__":
    solve()
