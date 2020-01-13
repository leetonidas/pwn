#!/usr/bin/env python3

import socket
import re
import numpy as np

def recv_until(sock, delim):
	tmp = b''
	while delim not in tmp:
		try:
			r = sock.recv(1)
			if not r:
				return tmp
			tmp += r
		except InterruptedError:
			pass
	return tmp

def recv_all(sock):
	tmp = b''
	while True:
		try:
			r = sock.recv(1)
			if not r:
				break
			tmp += r
		except InterruptedError:
			pass
#		except:
#			break
	return tmp

class FlagSock(socket.socket):
	flagbuf = b""
	flagbuflen = 100
	flagfile = "flags.txt"
	flagregex = b"hxp{[^}]+}"

	def __init__(self, a = None, b = None):
		if a is None:
			super(FlagSock, self).__init__()
		elif b is None:
			super(FlagSock, self).__init__(a)
		else:
			super(FlagSock, self).__init__(a,b)

	def flagregexfun(self, inp):
		res = re.search(self.flagregex, inp)
		return (res.end(), res.group()) if res is not None else None

	flagfun = flagregexfun

	def recv(self, bufsize, flags = 0):
		tmp = super(FlagSock, self).recv(bufsize, flags)
		self.flagbuf += tmp
		res = self.flagfun(self.flagbuf)
		if res is not None:
			print("Flag: " + str(res[1]))
			self.flagbuf = self.flagbuf[res[0]:]
			with open(self.flagfile, "ab") as ff:
				ff.write(res[1])
		self.flagbuf = self.flagbuf[-self.flagbuflen:]
		return tmp
import numpy as np

class crand:
    def __init__(self, seed=None):
        if seed == 0:
            seed = 1
        self.front = 3
        self.back = 0
        if seed is None:
            self.rands = [*map(np.int32, [-1726662223, 379960547, 1735697613, 1040273694, 1313901226,
                        1627687941, -179304937, -2073333483, 1780058412, -1989503057,
                        -615974602, 344556628, 939512070, -1249116260, 1507946756,
                        -812545463, 154635395, 1388815473, -1926676823, 525320961,
                        -1009028674, 968117788, -123449607, 1284210865, 435012392,
                        -2017506339, -911064859, -370259173, 1132637927, 1398500161,
                        -205601318])]
        else:
            self.rands = [np.int32(seed)]
            word = np.int32(seed)
            for i in range(1, 31):
                self.rands.append((16807 * self.rands[-1]) % 2147483647)
            for i in range(len(self.rands) * 10):
                self.next() 

    def __iter__(self):
    	return self

    def __next__(self):
        self.rands[self.front] = np.int32(self.rands[self.front] + self.rands[self.back])
        result = np.uint32(self.rands[self.front]) >> 1
        self.front = (self.front + 1) % len(self.rands)
        self.back = (self.back + 1) % len(self.rands)
        return result
