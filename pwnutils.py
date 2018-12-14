#!/usr/bin/env python3

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
