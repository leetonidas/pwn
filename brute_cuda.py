import pycuda.driver as cuda
import pycuda.compiler as cudac
import pycuda.gpuarray as gpuarray
import pycuda.autoinit

import numpy as np
import struct
import binascii
import base64
import sys
import os
from IPython import embed

def get_script_path():
    return os.path.dirname(os.path.realpath(sys.argv[0]))

i = 1
msg = np.array([i >> 64] + [i & 0xffffffff] + [0] * 12 + [24], dtype=np.dtype("uint32"))
#print(msg)

def dev_fits(d):
    return d.endian_little

def solve_pow(prefix, bits, ha="sha256"):
    print(f"bruting {ha} for {bits} 0 bits")

    # prefix input
    prefix = prefix.ljust(((len(prefix) + 3) >> 2) << 2, b"0")
    pref = np.array([int.from_bytes(prefix[i:i + 4], "big") for i in range(0, len(prefix), 4)], np.uint32)

    # output
    res = np.array([0,0,0], "uint32")

    # load program
    with open(f"{ha}.cu", "r") as f:
        m = cudac.SourceModule(f.read())
    fun = m.get_function("crypt_kernel")
    
    mask = (0xffffffff << (32 - bits)) & 0xffffffff

    # draufficken
    rnd = 0
    while True:
        fun(np.uint64(rnd), cuda.In(pref), np.uint64(pref.shape[0]), np.uint32(mask), cuda.InOut(res), block=(256,1,1), grid=(40,1,1))
        if res[0] != 0:
            break
        rnd += 1

    # print(res_np)
    # print(rnd)
    res = prefix + f"{res[1]:04x}{res[2]:04x}{rnd:08x}".encode()
    return res

if __name__ == "__main__":
    if len(sys.argv) >= 3:
        ha = "sha256"
        if len(sys.argv) == 4:
            ha = sys.argv[3]
        print(solve_pow(sys.argv[1].encode(), int(sys.argv[2]), ha).decode())