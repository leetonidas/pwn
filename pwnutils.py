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
		except:
			break
	return tmp
