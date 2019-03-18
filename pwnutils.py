#!/usr/bin/env python3

import socket
import re

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
		self.flagbuf = self.flagbuf[:self.flagbuflen]
		return tmp
