import re
# import multiprocessing
import time
from urllib.parse import urlparse#, urlunparse
# import proxy
# from multiprocessing import Process
# import ssl
# import socket
# from time import sleep
# import threading
from gevent.server import StreamServer
from gevent import sleep, socket
# monkey.patch_socket()
# monkey.patch_ssl()

def parse_header(raw_headers):
	request_lines = raw_headers.split('\r\n')
	first_line = request_lines[0].split(' ')
	method = first_line[0]
	full_path = first_line[1]
	version = first_line[2]
	# print("%s %s" % (method, full_path))
	(scm, netloc, path, params, query, fragment) \
		= urlparse(full_path, 'http')
	if method == 'CONNECT':
		address = (path.split(':')[0], int(path.split(':')[1]))
	else:
		# 如果url中有‘：’就指定端口，没有则为默认80端口
		i = netloc.find(':')
		if i >= 0:
			address = netloc[:i], int(netloc[i + 1:])
		else:
			address = netloc, 80
	return method, version, scm, address, path, params, query, fragment


host_p = re.compile('http://.+?/')
connection_p = re.compile('Connection: .+?\r\n')
def make_headers(headers):
	# headers = headers.replace('Proxy-', '')
	# headers = connection_p.sub('', headers)
	headers = headers.split('\n')
	headers[0] = host_p.sub('/', headers[0])
	headers = '\n'.join(headers)
	return headers


def childproxy(conn, addr, headers):
	s = socket.socket()
	s.connect( ('a.bjgong.tk', 8787 ) )
	s.sendall( headers.encode() )
	s.settimeout(0.1)
	conn.settimeout(0.1)
	while 1:
		try:
			for buf in iter(lambda:s.recv(1024*8),b''):
				# print('server:',len(buf))
				conn.sendall(buf)
			# print('server:b\'\'')
			# print('server: {} close'.format(addr))
			print('{} close'.format(addr) )
			return
		except socket.timeout:
			try:
				for buf in iter(lambda:conn.recv(1024*8),b''):
					# print("conn:",len(buf))
					s.sendall(buf)
				# print('conn:b\'\'')
				# print('client: {} close'.format(addr))
				print('{} close'.format(addr) )
				return
			except socket.timeout:
				sleep(0.1)
				continue
			except ConnectionResetError:
				print('{} close'.format(addr) )
				return
			


def httpsproxy(conn, addr, raw_headers):
	method, version, scm, address, path, params, query, fragment =\
		parse_header(raw_headers)	
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.settimeout(5)
	try:
		s.connect(address)
	except socket.timeout:
		black_list[address[0]] = None
		with open('black.dat', 'w') as f:
			f.write( '\n'.join( [ i for i in black_list.keys() ] ) )
		childproxy(conn, addr, raw_headers)
		return
	else:
		conn.sendall(b'HTTP/1.1 200 Connection established\r\n\r\n')
		s.settimeout(0.1)
		conn.settimeout(0.1)
		while 1:
			try:
				for buf in iter(lambda:conn.recv(1024*8),b''):
					# print("conn:",len(buf))
					s.sendall(buf)
				# print('conn:b\'\'')
				# print('client: {} close'.format(addr))
				print('server: {} client: {} close'.format(address[0], addr) )
				return
			except socket.timeout:
				try:
					for buf in iter(lambda:s.recv(1024*8),b''):
						# print('server:',len(buf))
						conn.sendall(buf)
					# print('server:b\'\'')
					# print('server: {} close'.format(address[0]))
					print('server: {} client: {} close'.format(address[0], addr) )
					return
				except socket.timeout:
					sleep(0.1)
					continue
				except ConnectionResetError:
					print('server: {} client: {} close'.format(address[0], addr) )
					return
			except ConnectionResetError:
				print('server: {} client: {} close'.format(address[0], addr) )
				return


def httpproxy(conn, addr, headers):
	try:
		method, version, scm, address, path, params, query, fragment =\
			parse_header(headers)
	except:
		return

	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	try:
		s.connect(address)
	except socket.error:
		s.close()
		return
	else:
		print('connect {} success'.format(address[0]))
		s.settimeout(0.1)
		conn.settimeout(0.1)
		raw_headers = headers
		headers = make_headers(headers)
		s.sendall(headers.encode())
		print(addr[0],
			  '[{}]'.format(time.strftime('%Y-%m-%d %H:%M:%S')),
			  raw_headers.split('\r\n')[0])
		while 1:
			try:
				for buf in iter(lambda:s.recv(1024), b''):
					# print('server:', address[0], len(buf))
					conn.sendall(buf)
				# print('server: {} close'.format(address[0]))
				print('server: {} client: {} close'.format(
					address[0], addr) )
				return
			except socket.timeout:
				try:
					while 1:
						buf = conn.recv(1024)#.decode('utf-8')
						if b'\r\n\r\n' in buf:
							buf = buf.split(b'\r\n\r\n')
							buf[0] = make_headers(buf[0].decode('utf-8')).encode()#+b'\r\n\r\n'+ buf[1]
							buf = b'\r\n\r\n'.join(buf)
							s.sendall(buf)
							print(addr[0],
								  '[{}]'.format(time.strftime('%Y-%m-%d %H:%M:%S')),
								  raw_headers.split('\r\n')[0])
						elif buf == b'':
							# print('client: {} close'.format(addr))
							print('server: {} client: {} close'.format(address[0], addr) )
							return
						else:
							s.sendall(buf)
				except socket.timeout:
					sleep(0.1)
					continue
			except BrokenPipeError:
				# print('client: {} close'.format(addr))
				print('server: {} client: {} close'.format(address[0], addr) )
				return


def handle(conn, addr):
	headers = ''
	for buf in iter( lambda:conn.recv(1).decode('utf-8'), ''):
		headers += buf
		if headers.endswith('\r\n\r\n'):
			break

	method = headers.split(' ')[0]
	if len(headers.split('\r\n')) <= 1:
		return
	else:
		pass
	if method == 'CONNECT':
		serv = headers.split('\r\n')[0].split(' ')[1].split(':')[0]
	else:
		serv = headers.split('\r\n')[1].split(' ')[1]

	if black_list.get( serv ):
		print( serv, 'black' )
		childproxy(conn, addr, headers)
	elif method == 'CONNECT':
		print(addr[0],
			  '[{}]'.format(time.strftime('%Y-%m-%d %H:%M:%S')),
			  headers.split('\r\n')[0])
		httpsproxy(conn, addr, headers)
	else:
		try:
			httpproxy(conn, addr, headers)
		except ConnectionResetError:
			childproxy(conn, addr, headers)

	
# def main1():
# 	s = socket.socket()
# 	s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
# 	s.bind(('0.0.0.0', 8087))
# 	s.listen(1500)
# 	while 1:
# 		conn, addr = s.accept()
# 		# multiprocessing.Process(target=handle,args=(conn,addr)).start()
# 		threading.Thread(target=handle,args=(conn,addr)).start()
		
# main1()
black_list = { i.strip():True for i in open('black.dat').readlines() }
StreamServer(('0.0.0.0', 8087), handle).serve_forever()
