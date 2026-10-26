#!/usr/bin/env python3
"""
REV-6 "Compiler Fingerprint" (Ghost Mantis) - analysis helper.

Usage:
    python3 solve.py [dir_with_mantis_binaries]      (default: ./player)

Needs: binutils (readelf, objdump) and, for version detection, one or more
       clang-N compilers on PATH  (sudo apt install clang-16 clang-17 clang-18 clang-19 clang-20)

What it does
  1. Static traits from the ELF files (comment section, PIE, RELRO, canary,
     frame pointers, CET, FORTIFY, glibc floor, shared prologue marker).
  2. Rebuilds reference programs that behave like the three tools with every
     clang-N / gcc found, normalises the disassembly of the user code, and
     scores it against the samples. The best-scoring compiler is the
     fingerprint.
  3. Prints a candidate flag. The separator/trait naming CREST expects is the
     author's choice, so adjust the final string if the platform rejects it.
"""
import difflib, glob, os, re, shutil, subprocess, sys, tempfile

D = sys.argv[1] if len(sys.argv) > 1 else "player"
BINS = {"alpha": "mantis_alpha", "beta": "mantis_beta", "gamma": "mantis_gamma"}
MARKER = bytes.fromhex("31c083c00090")          # xor eax,eax; add eax,0; nop

M = '__asm__ volatile("xor %%eax,%%eax\\n\\tadd $0,%%eax\\n\\tnop":::"eax")'
SRC = {
"alpha": f'''#include <stdio.h>
#include <string.h>
#define M {M}
__attribute__((noinline)) int f(int x){{M;return x*3+7;}}
__attribute__((noinline)) int g(const char*s){{M;size_t n=strlen(s);int h=0;for(size_t i=0;i<n;i++)h^=(signed char)s[i];return h;}}
int main(){{char b[64];puts("Ghost Mantis :: Data Handler");printf("Enter token: ");scanf("%63s",b);int r=f((int)strlen(b))^g(b);printf("Processed: %d\\n",r);return 0;}}
''',
"beta": f'''#include <stdio.h>
#define M {M}
__attribute__((noinline)) unsigned long f(unsigned long x){{M;x^=x<<13;x^=x>>7;x^=x<<17;return x;}}
int main(){{unsigned long s;puts("Ghost Mantis :: Relay Utility");printf("Enter numeric seed: ");scanf("%lu",&s);printf("Output: %lu\\n",f(s));return 0;}}
''',
"gamma": f'''#include <stdio.h>
#include <stdlib.h>
#define M {M}
__attribute__((noinline)) int cmp(const void*a,const void*b){{M;return *(const int*)a-*(const int*)b;}}
__attribute__((noinline)) void srt(int*v){{M;qsort(v,8,4,cmp);}}
int main(){{int v[8];puts("Ghost Mantis :: Sort Engine");puts("Enter 8 integers:");for(int i=0;i<8;i++)scanf("%d",&v[i]);srt(v);printf("Sorted checksum: ");int s=0;for(int i=0;i<8;i++)s+=v[i];printf("%d\\n",s);return 0;}}
''',
}
FLAGS = ["-O2", "-fno-omit-frame-pointer", "-fstack-protector-strong", "-U_FORTIFY_SOURCE"]


def run(*a):
    return subprocess.run(a, capture_output=True, text=True).stdout


# ---------------------------------------------------------------- traits
def traits(path):
    t = {}
    secs = run("readelf", "-SW", path)
    t["comment_section"] = ".comment" in secs
    t["pie"] = "DYN (Position-Independent" in run("readelf", "-h", path)
    ph = run("readelf", "-lW", path)
    dyn = run("readelf", "-dW", path)
    t["relro"] = "GNU_RELRO" in ph
    t["full_relro"] = t["relro"] and ("BIND_NOW" in dyn or "NOW" in dyn)
    syms = run("readelf", "--dyn-syms", "-W", path)
    t["canary"] = "__stack_chk_fail" in syms
    t["fortify"] = "_chk@" in syms
    t["glibc_floor"] = max((tuple(map(int, m.split("."))) for m in re.findall(r"GLIBC_(\d+(?:\.\d+)+)", syms)), default=None)
    props = run("readelf", "-n", path)
    t["cet_ibt_shstk"] = ("IBT" in props) or ("SHSTK" in props)
    raw = open(path, "rb").read()
    t["marker_hits"] = raw.count(MARKER)
    dis = run("objdump", "-d", "-M", "intel", "--no-show-raw-insn", "-j", ".text", path)
    t["frame_ptr"] = len(re.findall(r"push\s+rbp\n\s+[0-9a-f]+:\s+mov\s+rbp,rsp", dis)) >= 2
    init = run("objdump", "-d", "--no-show-raw-insn", "-j", ".init", path)
    t["crt_endbr"] = "endbr64" in init
    return t


# --------------------------------------------------------- normalisation
def user_code(dis):
    """lines of user code: everything after frame_dummy's 'endbr64; jmp' stub."""
    lines = []
    for l in dis.splitlines():
        m = re.match(r"\s*[0-9a-f]+:\s+(.*)", l)
        if m:
            lines.append(m.group(1).split("#")[0].strip())
    start = 0
    for i in range(len(lines) - 1):
        if lines[i].startswith("endbr64") and lines[i + 1].startswith("jmp"):
            start = i + 2
    out = []
    for l in lines[start:]:
        if re.match(r"(cs |data16|nop)", l):         # alignment padding differs by assembler
            continue
        mn = l.split()[0]
        if mn == "call" or mn.startswith("j"):
            l = mn                                    # drop targets
        l = re.sub(r"<[^>]*>", "", l)
        l = re.sub(r"\[rip[^\]]*\]", "[rip]", l)
        l = re.sub(r"0x[0-9a-f]{3,}", "ADDR", l)
        out.append(re.sub(r"\s+", " ", l))
    return out


def dis(path):
    return run("objdump", "-d", "-M", "intel", "--no-show-raw-insn", "-j", ".text", path)


def compilers():
    found = []
    for n in range(10, 25):
        if shutil.which(f"clang-{n}"):
            found.append(f"clang-{n}")
    if shutil.which("clang") and not found:
        found.append("clang")
    for n in range(9, 16):
        if shutil.which(f"gcc-{n}"):
            found.append(f"gcc-{n}")
    return found


def score(cc, name, ref, tmp):
    c = os.path.join(tmp, f"{name}.c")
    open(c, "w").write(SRC[name])
    exe = os.path.join(tmp, f"{name}.{cc}")
    r = subprocess.run([cc, *FLAGS, "-o", exe, c], capture_output=True, text=True)
    if r.returncode:
        return 0.0
    mine = user_code(dis(exe))
    return difflib.SequenceMatcher(None, ref, mine, autojunk=False).ratio()


def main():
    print("== static traits ==")
    all_t = {}
    for k, f in BINS.items():
        p = os.path.join(D, f)
        if not os.path.exists(p):
            sys.exit(f"missing {p}")
        all_t[k] = traits(p)
        print(k, all_t[k])
    common = {key for key in all_t["alpha"] if all(all_t[b][key] == all_t["alpha"][key] for b in all_t) and key != "marker_hits"}
    print("\nshared by all three:", sorted(common))
    print("prologue marker (xor eax,eax; add eax,0; nop) count per binary:",
          {k: all_t[k]["marker_hits"] for k in all_t})

    refs = {k: user_code(dis(os.path.join(D, f))) for k, f in BINS.items()}
    ccs = compilers()
    if not ccs:
        print("\nNo clang-N/gcc-N found; install clang-16..20 to run version detection.")
        return
    print("\n== codegen match (1.000 = identical modulo padding/labels) ==")
    best = None
    with tempfile.TemporaryDirectory() as tmp:
        for cc in ccs:
            sc = {n: score(cc, n, refs[n], tmp) for n in SRC}
            tot = sum(sc.values()) / len(sc)
            print(f"{cc:10s}", {n: round(v, 4) for n, v in sc.items()}, "avg", round(tot, 4))
            if best is None or tot > best[1]:
                best = (cc, tot)
    ver = re.search(r"(\d+)$", best[0])
    comp = "clang" if best[0].startswith("clang") else "gcc"
    t = all_t["alpha"]
    traits_s = ["O2"]
    if t["frame_ptr"]: traits_s.append("fp")
    if t["canary"]: traits_s.append("ssp")
    if t["pie"]: traits_s.append("pie")
    print(f"\nBest compiler match: {best[0]}  (avg similarity {best[1]:.4f})")
    print(f"Candidate flag: CREST{{{comp}_{ver.group(1) if ver else 'x'}_{'_'.join(traits_s)}}}")
    print("(compiler/version/traits are derived from evidence; the exact token spelling is the author's choice)")


if __name__ == "__main__":
    main()
