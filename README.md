# objcpuid
a tool that analyzes an object file to determine what cpu features are required for its instructions.

the primary use case is making sure assembly code is compaitable with whatever extensions you're targeting

it only supports x86_64 and ELF input files.
## usage
```
./main.py --summary tests/countlines_avx2.o
file:  tests/countlines_avx2.o
.
.
avx:    22
avx2:   35

python main.py --summary tests/countlines_sse2.o 
file:  tests/countlines_sse2.o
.
.
sse2:   70

python main.py --watch avx2 tests/countlines_avx2.o

file:  tests/countlines_avx2.o
avx2 instruction at function countlines:
0x40:   vpcmpeqb        ymm0, ymm4, ymmword ptr [rax]

avx2 instruction at function countlines:
0x48:   vpand   ymm0, ymm0, ymm3
.
.
.
avx2 instruction at function countchars:
0x115:  vpbroadcastd    ymm3, xmm3

avx2 instruction at function countchars:
0x130:  vpmovsxbw       ymm1, xmm0
.
.
.
```

## dependencies
* [Capstone](https://github.com/aquynh/capstone)
* [Pyelftools](https://github.com/eliben/pyelftools)
