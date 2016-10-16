import re
import json
import time
import socks
from urllib.parse import urlparse#, urlunparse
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
proxy_p = re.compile('Proxy-.+?\n')
def make_headers(headers):
	if '\nConnection' in headers:
		headers = proxy_p.sub('', headers)
	else:
		headers = headers.replace('Proxy-', '')
	# headers = connection_p.sub('', headers)
	headers = headers.split('\n')
	headers[0] = host_p.sub('/', headers[0])
	headers = '\n'.join(headers)
	# print(headers)
	return headers


def create_pipe(conn, serv, conn_name='', serv_name=''):
	serv.settimeout(0.1)
	conn.settimeout(0.1)
	while 1:
		try:
			for buf in iter(lambda:conn.recv(1024*4),b''):
				serv.sendall(buf)
			print('server: {} client: {} close'.format(serv_name, conn_name) )
			return
		except socket.timeout:
			try:
				for buf in iter(lambda:serv.recv(1024),b''):
					conn.sendall(buf)
				print('server: {} client: {} close'.format(serv_name, conn_name) )
				return
			except socket.timeout:
				sleep(0.1)
				continue
			except ConnectionResetError:
				print('server: {} client: {} close'.format(serv_name, conn_name) )
				return
		except (ConnectionResetError, BrokenPipeError):
			print('server: {} client: {} close'.format(serv_name, conn_name) )
			return	


server_ = json.loads( open('aqua.json').read() )
server = server_['server']
port = int(server_['port'])
proxy_type = server_['type']
if proxy_type == 'socks':
	socks.set_default_proxy(socks.SOCKS5, server, port)
else:
	pass
def childproxy(conn, headers, conn_name='', serv_name=''):
	if proxy_type == 'http':
		s = socket.socket()
		s.connect( (server, port ) )
		s.sendall( headers.encode() )
		create_pipe(conn, s, conn_name, serv_name)
	elif proxy_type == 'socks':
		method, version, scm, address, path, params, query, fragment = parse_header(headers)
		s = socks.socksocket()
		s.connect(address)
		print('connect {} success'.format(serv_name))
		if headers.startswith('CONNECT'):
			conn.sendall(b'HTTP/1.1 200 Connection established\r\n\r\n')
			create_pipe(conn, s, conn_name=conn_name, serv_name=serv_name)
		else:
			s.settimeout(0.1)
			conn.settimeout(0.1)
			raw_headers = headers
			headers = make_headers(headers)
			s.sendall(headers.encode())
			print(conn_name,
				  '[{}]'.format(time.strftime('%Y-%m-%d %H:%M:%S')),
				  raw_headers.split('\r\n')[0])
			while 1:
				try:
					for buf in iter(lambda:s.recv(1024*16), b''):
						conn.sendall(buf)
					print('server: {} client: {} close'.format(
						serv_name, conn_name) )
					return
				except socket.timeout:
					try:
						while 1:
							buf = conn.recv(1024)#.decode('utf-8')
							if b'\r\n\r\n' in buf:
								buf = buf.split(b'\r\n\r\n')
								buf[0] = make_headers(buf[0].decode('utf-8','ignore')).encode()#+b'\r\n\r\n'+ buf[1]
								buf = b'\r\n\r\n'.join(buf)
								s.sendall(buf)
								print(conn_name,
									  '[{}]'.format(time.strftime('%Y-%m-%d %H:%M:%S')),
									  raw_headers.split('\r\n')[0])
							elif buf == b'':
								# print('client: {} close'.format(addr))
								print('server: {} client: {} close'.format(serv_name, conn_name) )
								return
							else:
								s.sendall(buf)
					except socket.timeout:
						sleep(0.1)
						continue
				except (BrokenPipeError, ConnectionResetError):
					# print('client: {} close'.format(addr))
					print('server: {} client: {} close'.format(serv_name, conn_name) )
					return
				# except ConnectionResetError:
				# 	# black_list[address[0]] = True
				# 	# with open('black.dat', 'w') as f:
				# 	# 	f.write( '\n'.join( [ i for i in black_list.keys() ] ) )
				# 	# childproxy(conn, raw_headers, conn_name=addr, serv_name=address[0])
				# 	print('server: {} client: {} close'.format(serv_name, conn_name) )
				# 	return
		
	else:
		return


def httpsproxy(conn, addr, raw_headers):
	method, version, scm, address, path, params, query, fragment =\
		parse_header(raw_headers)	
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.settimeout(7)
	# print(pre_dict)
	try:
		s.connect(address)
	except socket.timeout:
		s.settimeout(None)
		# if pre_dict.get(address[0]):
		# 	black_list[address[0]] = True
		# 	with open('black.dat', 'w') as f:
		# 		f.write( '\n'.join( [ i for i in black_list.keys() ] ) )
		if iscdn(address[0]):
			pass
		else:
			addblack(address[0])
		# else:
		# 	pre_dict[address[0]] = True
		childproxy(conn, raw_headers, conn_name=addr, serv_name=address[0])
		return
	else:
		s.settimeout(None)
		conn.sendall(b'HTTP/1.1 200 Connection established\r\n\r\n')
		create_pipe(conn, s, conn_name=addr, serv_name=address[0])


def httpproxy(conn, addr, headers):
	try:
		method, version, scm, address, path, params, query, fragment =\
			parse_header(headers)
	except:
		return

	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.settimeout(7)
	# print(pre_dict)
	try:
		s.connect(address)
	# except socket.error:
	# 	print(headers, 'close')
	# 	s.close()
	# 	return
	except socket.timeout:
		s.settimeout(None)
		print(address[0],'timeout')
		# if pre_dict.get(address[0]):
		# 	black_list[address[0]] = True
		# 	with open('black.dat', 'w') as f:
		# 		f.write( '\n'.join( [ i for i in black_list.keys() ] ) )
		# else:
		# 	pre_dict[address[0]] = True
		if iscdn(address[0]):
			pass
		else:
			addblack(address[0])
		childproxy(conn, headers, conn_name=addr, serv_name=address[0])
		return
	else:
		s.settimeout(None)
		print('connect {} success'.format(address[0]))
		s.settimeout(0.1)
		conn.settimeout(0.1)
		raw_headers = headers
		headers = make_headers(headers)
		s.sendall(headers.encode())
		print(addr,
			  '[{}]'.format(time.strftime('%Y-%m-%d %H:%M:%S')),
			  raw_headers.split('\r\n')[0])
		while 1:
			try:
				for buf in iter(lambda:s.recv(1024*16), b''):
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
						print(buf)
						if b'\r\n\r\n' in buf:
							buf = buf.split(b'\r\n\r\n')
							# buf[0] = make_headers(buf[0].decode('utf-8','ignore')).encode()#+b'\r\n\r\n'+ buf[1]
							buf = b'\r\n\r\n'.join(buf)
							s.sendall(buf)
							print(addr,
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
			except ConnectionResetError:
				# black_list[address[0]] = True
				# with open('black.dat', 'w') as f:
				# 	f.write( '\n'.join( [ i for i in black_list.keys() ] ) )
				childproxy(conn, raw_headers, conn_name=addr, serv_name=address[0])
				return


def isblack(domain):
	if [ i for i in black_list if domain.endswith(i) ]:
		return 1
	else:
		return 0


def iscdn(domain):
	if [ i for i in cdn_list if domain.endswith(i) ]:
		return 1
	else:
		return 0


def addblack(domain):
	p = re.compile('[^\.]+\.[^\.]+$')
	domain_end = '.' + p.findall(domain)[0]
	black_list.add(domain_end)
	with open('black.dat', 'w') as f:
		f.write( '\n'.join( [ i for i in black_list ] ) )	  


def handle(conn, addr):
	headers = ''
	for buf in iter( lambda:conn.recv(1).decode('utf-8','ignore'), ''):
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

	# if black_list.get( serv ):
	if isblack(serv):
		print( serv, 'black' )
		print(addr[0],
			  '[{}]'.format(time.strftime('%Y-%m-%d %H:%M:%S')),
			  headers.split('\r\n')[0])
		childproxy(conn, headers, conn_name=addr[0])
	elif method == 'CONNECT':
		print(addr[0],
			  '[{}]'.format(time.strftime('%Y-%m-%d %H:%M:%S')),
			  headers.split('\r\n')[0])
		httpsproxy(conn, addr[0], headers)
	else:
		# try:
		httpproxy(conn, addr[0], headers)

	
def main1():
	s = socket.socket()
	s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	s.bind(('0.0.0.0', 2048))
	s.listen(1500)
	while 1:
		conn, addr = s.accept()
		# multiprocessing.Process(target=handle,args=(conn,addr)).start()
		threading.Thread(target=handle,args=(conn,addr)).start()
		
black_list = { i.strip() for i in open('black.dat').readlines() }
cdn_list = { i.strip() for i in open('cdnlist.dat').readlines() }
pre_dict = {}
# main1()
StreamServer(('0.0.0.0', 2048), handle).serve_forever()
