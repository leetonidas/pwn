import pyopencl as cl
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

def solve_pow(prefix, bits):

    devs = sorted([d for p in cl.get_platforms() for d in p.get_devices() if dev_fits(d)], key=lambda x: x.max_work_group_size)
    if len(devs) == 0:
        print("no suitable dev found")

    wgsize = devs[0].max_work_group_size    
    
    ctx = cl.Context(devs)
    queue = cl.CommandQueue(ctx)
    
    mf = cl.mem_flags
    # prefix input
    prefix = prefix.ljust(((len(prefix) + 3) >> 2) << 2, b"0")
    pref = np.array([int.from_bytes(prefix[i:i + 4], "big") for i in range(0, len(prefix), 4)], np.uint32)
    pref_g = cl.Buffer(ctx, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=pref)

    # output
    res_np = np.array([0,0,0], "uint32")
    res_g = cl.Buffer(ctx, mf.WRITE_ONLY, res_np.nbytes)

    # load program    
    with open("sha256.cl", "r") as f:
        prg = cl.Program(ctx, f.read()).build(cache_dir=os.path.join(get_script_path(), ".cl_cache"))
    
    mask = (0xffffffff << (32 - bits)) & 0xffffffff

    # draufficken
    rnd = 0
    while True:
        res = prg.sha256_crypt_kernel(queue, (wgsize,), None, np.uint64(rnd), pref_g, np.uint64(pref.shape[0]), np.uint32(mask), res_g)
        cl.enqueue_copy(queue, res_np, res_g)
        if res_np[0] != 0:
            break
        rnd += 1

    # print(res_np)
    # print(rnd)
    res = prefix + f"{res_np[1]:04x}{res_np[2]:04x}{rnd:08x}".encode()
    return res
