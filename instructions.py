from struct import unpack

known_instructions = {}

x86_r_r = {}
x64_r_r = {}
def build_r_r():
    regs = ['ax', 'cx', 'dx', 'bx', 'sp', 'bp', 'si', 'di']
    for i in range(len(regs)): # src
        for j in range(len(regs)): # dst
            x86val = f'e{regs[j]}, e{regs[i]}'
            x64val = f'r{regs[j]}, r{regs[i]}'
            key = (0xc0 + 8*i + j).to_bytes(1, 'little')
            x86_r_r[key] = x86val
            x64_r_r[key] = x64val
build_r_r()

x64_pop_r = {
    b'\x58': 'rax',
    b'\x59': 'rcx',
    b'\x5a': 'rdx',
    b'\x5b': 'rbx',
    b'\x5c': 'rsp',
    b'\x5d': 'rbp',
    b'\x5e': 'rsi',
    b'\x5f': 'rdi',
    b'\x41\x58': 'r8',
    b'\x41\x59': 'r9',
    b'\x41\x5a': 'r10',
    b'\x41\x5b': 'r11',
    b'\x41\x5c': 'r12',
    b'\x41\x5d': 'r13',
    b'\x41\x5e': 'r14',
    b'\x41\x5f': 'r15',
}

x64_push_r = {
    b'\x50': 'rax',
    b'\x51': 'rcx',
    b'\x52': 'rdx',
    b'\x53': 'rbx',
    b'\x54': 'rsp',
    b'\x55': 'rbp',
    b'\x56': 'rsi',
    b'\x57': 'rdi',
    b'\x41\x50': 'r8',
    b'\x41\x51': 'r9',
    b'\x41\x52': 'r10',
    b'\x41\x53': 'r11',
    b'\x41\x54': 'r12',
    b'\x41\x55': 'r13',
    b'\x41\x56': 'r14',
    b'\x41\x57': 'r15',
}

x86_mov_r_imm32 = {
    b'\xb8': 'eax',
    b'\xb9': 'ecx',
    b'\xba': 'edx',
    b'\xbb': 'ebx',
    b'\xbc': 'esp',
    b'\xbd': 'ebp',
    b'\xbe': 'esi',
    b'\xbf': 'edi',
    b'\x41\xb8': 'r8d',
    b'\x41\xb9': 'r9d',
    b'\x41\xba': 'r10d',
    b'\x41\xbb': 'r11d',
    b'\x41\xbc': 'r12d',
    b'\x41\xbd': 'r13d',
    b'\x41\xbe': 'r14d',
    b'\x41\xbf': 'r15d',
}

x86_and_r_imm8 = {
    b'\xe0': 'eax',
    b'\xe1': 'ecx',
    b'\xe2': 'edx',
    b'\xe3': 'ebx',
    b'\xe4': 'esp',
    b'\xe5': 'ebp',
    b'\xe6': 'esi',
    b'\xe7': 'edi',
    b'\x41\xe0': 'r8d',
    b'\x41\xe1': 'r9d',
    b'\x41\xe2': 'r10d',
    b'\x41\xe3': 'r11d',
    b'\x41\xe4': 'r12d',
    b'\x41\xe5': 'r13d',
    b'\x41\xe6': 'r14d',
    b'\x41\xe7': 'r15d',
}

x64_shl_r_imm8 = {
    b'\xe0': 'rax',
    b'\xe1': 'rcx',
    b'\xe2': 'rdx',
    b'\xe3': 'rbx',
    b'\xe4': 'rsp',
    b'\xe5': 'rbp',
    b'\xe6': 'rsi',
    b'\xe7': 'rdi',
}

def endbr64(file, cur):
    """
    f3 0f
    """
    assert file.read(2) == b'\x1e\xfa', 'malformed endbr64'
    return 'endbr64'
known_instructions[b'\xf3\x0f'] = endbr64

def and_rsp_imm8(file, cur):
    """
    48 83 e4
    """
    x = unpack("<b", file.read(1))[0]
    return f'and rsp, {x}'
known_instructions[b'\x48\x83\xe4'] = and_rsp_imm8

def and_r32_r32(file, cur):
    """
    21
    """
    reg = file.read(1)
    return 'and ' + x86_r_r[reg]
known_instructions[b'\x21'] = and_r32_r32

def and_r32_imm8(file, cur):
    """
    83 RR
    """
    reg = x86_and_r_imm8[cur[1].to_bytes(1, 'little')]
    x = unpack("<b", file.read(1))[0]
    return f'and {reg}, {x}'
for key, value in x86_and_r_imm8.items():
    known_instructions[b'\x83'+key] = and_r32_imm8

def and_Hr32_imm8(file, cur):
    """
    41 83
    """
    reg = x86_and_r_imm8['\x41' + file.read(1)]
    x = unpack("<b", file.read(1))[0]
    return f'and {reg}, {x}'
known_instructions[b'\x41\x83'] = and_Hr32_imm8

def add_r32_r32(file, cur):
    """
    01
    """
    reg = file.read(1)
    return 'add ' + x86_r_r[reg]
known_instructions[b'\x01'] = add_r32_r32

def add_r64_r64(file, cur):
    """
    48 01
    """
    reg = file.read(1)
    return 'add ' + x64_r_r[reg]
known_instructions[b'\x48\x01'] = add_r64_r64

def add_r64_imm8(file, cur):
    """
    48 83 RR
    """
    x = unpack("<b", file.read(1))[0]
    reg = x64_r_r[cur[2].to_bytes(1, 'little')].split(',')[0]
    return f'add {reg}, {x}'
for i in range(0xc0, 0xc8):
    known_instructions[b'\x48\x83' + i.to_bytes(1, 'little')] = add_r64_imm8

def and_al_rbp_relbyte_byte(file, cur):
    """
    22 45
    """
    off = unpack("<b", file.read(1))[0]
    ret = 'and al, byte [rbp'
    if off > 0:
        ret += '+' + hex(off)
    elif off < 0:
        ret += '-' + hex(-off)
    ret += ']'
    return ret
known_instructions[b'\x22\x45'] = and_al_rbp_relbyte_byte

def add_rbp_reldword_byte(file, cur):
    """
    83 45
    """
    off = unpack("<b", file.read(1))[0]
    x = unpack("<b", file.read(1))[0]
    ret = 'add dword [rbp'
    if off > 0:
        ret += '+' + hex(off)
    elif off < 0:
        ret += '-' + hex(-off)
    ret += f'], {hex(x)}'
    return ret
known_instructions[b'\x83\x45'] = add_rbp_reldword_byte

def cmovbe_rax_rdx(file, cur):
    """
    48 0f 46 c2
    """
    return 'cmovbe rax, rdx'
known_instructions[b'\x48\x0f\x46\xc2'] = cmovbe_rax_rdx

def cmp_r64_r64(file, cur):
    """
    48 39
    """
    reg = file.read(1)
    return 'cmp ' + x64_r_r[reg]
known_instructions[b'\x48\x39'] = cmp_r64_r64

def cmp_m8_rbp_relbyte_byte(file, cur):
    """
    80 7d
    """
    off = unpack("<b", file.read(1))[0]
    x = unpack("<b", file.read(1))[0]
    ret = 'cmp byte [rbp'
    if off > 0:
        ret += '+' + hex(off)
    elif off < 0:
        ret += '-' + hex(-off)
    ret += f'], {hex(x)}'
    return ret
known_instructions[b'\x80\x7d'] = cmp_m8_rbp_relbyte_byte

def cmp_m32_rbp_relbyte_byte(file, cur):
    """
    83 7d
    """
    off = unpack("<b", file.read(1))[0]
    x = unpack("<b", file.read(1))[0]
    ret = 'cmp dword [rbp'
    if off > 0:
        ret += '+' + hex(off)
    elif off < 0:
        ret += '-' + hex(-off)
    ret += f'], {hex(x)}'
    return ret
known_instructions[b'\x83\x7d'] = cmp_m32_rbp_relbyte_byte

def cmp_al_rbp_relbyte(file, cur):
    """
    3a 45
    """
    off = unpack("<b", file.read(1))[0]
    ret = 'cmp al, byte [rbp'
    if off > 0:
        ret += '+' + hex(off)
    elif off < 0:
        ret += '-' + hex(-off)
    ret += ']'
    return ret
known_instructions[b'\x3a\x45'] = cmp_al_rbp_relbyte

def sub_rsp_byte(file, cur):
    """
    48 83 ec
    """
    x = unpack("<b", file.read(1))[0]
    return f'sub rsp, {hex(x)}'
known_instructions[b'\x48\x83\xec'] = sub_rsp_byte

def sub_rsp_dword(file, cur):
    """
    48 81 ec
    """
    x = unpack("<i", file.read(4))[0]
    return f'sub rsp, {hex(x)}'
known_instructions[b'\x48\x81\xec'] = sub_rsp_dword

def add_rsp_byte(file, cur):
    """
    48 83 c4
    """
    x = unpack("<b", file.read(1))[0]
    return f'add rsp, {hex(x)}'
known_instructions[b'\x48\x83\xc4'] = add_rsp_byte

def cdqe(file, cur):
    """
    48 98
    """
    return 'cdqe'
known_instructions[b'\x48\x98'] = cdqe

def jae_byte_offset(file, cur):
    """
    73
    """
    x = unpack("<b", file.read(1))[0]
    return f'jae {hex(x+file.tell())}'
known_instructions[b'\x73'] = jae_byte_offset

def je_byte_offset(file, cur):
    """
    74
    """
    x = unpack("<b", file.read(1))[0]
    return f'je {hex(x+file.tell())}'
known_instructions[b'\x74'] = je_byte_offset

def jne_byte_offset(file, cur):
    """
    75
    """
    x = unpack("<b", file.read(1))[0]
    return f'jne {hex(x+file.tell())}'
known_instructions[b'\x75'] = jne_byte_offset

def jbe_byte_offset(file, cur):
    """
    76
    """
    x = unpack("<b", file.read(1))[0]
    return f'jbe {hex(x+file.tell())}'
known_instructions[b'\x76'] = jbe_byte_offset

def jns_byte_offset(file, cur):
    """
    79
    """
    x = unpack("<b", file.read(1))[0]
    return f'jns {hex(x+file.tell())}'
known_instructions[b'\x79'] = jns_byte_offset

def jmp_byte_offset(file, cur):
    """
    eb
    """
    x = unpack("<b", file.read(1))[0]
    return f'jmp {hex(x+file.tell())}'
known_instructions[b'\xeb'] = jmp_byte_offset

def jmp_dword_offset(file, cur):
    """
    e9
    """
    x = unpack("<i", file.read(4))[0]
    return f'jmp {hex(x+file.tell())}'
known_instructions[b'\xe9'] = jmp_dword_offset

def je_dword_offset(file, cur):
    """
    0f 84
    """
    x = unpack("<i", file.read(4))[0]
    return f'je {hex(x+file.tell())}'
known_instructions[b'\x0f\x84'] = je_dword_offset

def leave(file, cur):
    """
    c9
    """
    return 'leave'
known_instructions[b'\xc9'] = leave

def mov_rax_qword_rel_rip(file, cur):
    """
    48 8b 05
    """
    x = unpack('<i', file.read(4))[0]
    return f'mov rax, qword [{hex(x+file.tell())}]'
known_instructions[b'\x48\x8b\x05'] = mov_rax_qword_rel_rip

def mov_eax_dword_rel_rip(file, cur):
    """
    8b 05
    """
    x = unpack('<i', file.read(4))[0]
    return f'mov eax, dword [{hex(x+file.tell())}]'
known_instructions[b'\x8b\x05'] = mov_eax_dword_rel_rip

def mov_rax_qword_rax(file, cur):
    """
    48 8b 00
    """
    return f'mov rax, qword [rax]'
known_instructions[b'\x48\x8b\x00'] = mov_rax_qword_rax

def mov_eax_dword_rbp_relbyte(file, cur):
    """
    8b 45
    """
    x = unpack("<b", file.read(1))[0]
    ret = 'mov eax, dword [rbp'
    if x > 0:
        ret += '+' + hex(x)
    elif x < 0:
        ret += '-' + hex(-x)
    ret += ']'
    return ret
known_instructions[b'\x8b\x45'] = mov_eax_dword_rbp_relbyte

def mov_r9_rdx(file, cur):
    """
    49 89 d1
    """
    return 'mov r9, rdx'
known_instructions[b'\x49\x89\xd1'] = mov_r9_rdx

def mov_r32_imm32(file, cur):
    """
    Many versions, see x86_mov_r_imm32
    """
    reg = x86_mov_r_imm32[cur]
    x = unpack('<i', file.read(4))[0]
    return f'mov {reg}, {hex(x)}'
for key, value in x86_mov_r_imm32.items():
    known_instructions[key] = mov_r32_imm32

def mov_mem_rax_plus_rdx_imm8(file, cur):
    """
    c6 04 10
    """
    x = unpack('<b', file.read(1))[0]
    return f'mov byte [rax+rdx], {hex(x)}'
known_instructions[b'\xc6\x04\x10'] = mov_mem_rax_plus_rdx_imm8

def mov_mem_rax_plus_dword_offset_imm8(file, cur):
    """
    c6 80
    """
    off = unpack('<i', file.read(4))[0]
    x = unpack('<b', file.read(1))[0]
    ret = 'mov byte [rax'
    if off > 0:
        ret += '+' + hex(off)
    elif off < 0:
        ret += '-' + hex(-off)
    ret += f'], {hex(x)}'
    return ret
known_instructions[b'\xc6\x80'] = mov_mem_rax_plus_dword_offset_imm8

def mov_mem_rdx_plus_rax_cl(file, cur):
    """
    88 0c 02
    """
    return 'mov byte [rdx+rax], cl'
known_instructions[b'\x88\x0c\x02'] = mov_mem_rdx_plus_rax_cl

def mov_rbp_relbyte_m32_imm32(file, cur):
    """
    c7 45
    """
    off = unpack("<b", file.read(1))[0]
    x = unpack("<i", file.read(4))[0]
    ret = 'mov dword [rbp'
    if off > 0:
        ret += '+' + hex(off)
    elif off < 0:
        ret += '-' + hex(-off)
    ret += '], ' + hex(x)
    return ret
known_instructions[b'\xc7\x45'] = mov_rbp_relbyte_m32_imm32

def mov_rm32_r32(file, cur):
    """
    89
    """
    reg = file.read(1)
    if reg in x86_r_r:
        return 'mov ' + x86_r_r[reg]
    if reg == b'\xbd':
        return mov_rbp_reldword_m32_edi(file, cur)
    if reg == b'\x02':
        return mov_m32_rdx_eax(file, cur)
    raise KeyError()
known_instructions[b'\x89'] = mov_rm32_r32

def mov_rbp_reldword_m32_edi(file, cur):
    """
    89 bd
    """
    x = unpack("<i", file.read(4))[0]
    ret = 'mov dword [rbp'
    if x > 0:
        ret += '+' + hex(x)
    elif x < 0:
        ret += '-' + hex(-x)
    ret += '], edi'
    return ret

def mov_m32_rdx_eax(file, cur):
    """
    89 02
    """
    return 'mov dword [rdx], eax'

def mov_rm64_r64(file, cur):
    """
    48 89
    """
    reg = file.read(1)
    if reg in x64_r_r:
        return 'mov ' + x64_r_r[reg]
    if reg == b'\x7d':
        return mov_rbp_relbyte_m64_rdi(file, cur)
    if reg == b'\x45':
        return mov_rbp_relbyte_m64_rax(file, cur)
    if reg == b'\x75':
        return mov_rbp_relbyte_m64_rsi(file, cur)
    if reg == b'\xb5':
        return mov_rbp_reldword_m64_rsi(file, cur)
    raise KeyError()
known_instructions[b'\x48\x89'] = mov_rm64_r64

def mov_rbp_relbyte_m64_rdi(file, cur):
    """
    48 89 7d
    """
    x = unpack("<b", file.read(1))[0]
    ret = 'mov qword [rbp'
    if x > 0:
        ret += '+' + hex(x)
    elif x < 0:
        ret += '-' + hex(-x)
    ret += '], rdi'
    return ret

def mov_rbp_relbyte_m64_rsi(file, cur):
    """
    48 89 75
    """
    x = unpack("<b", file.read(1))[0]
    ret = 'mov qword [rbp'
    if x > 0:
        ret += '+' + hex(x)
    elif x < 0:
        ret += '-' + hex(-x)
    ret += '], rsi'
    return ret

def mov_rbp_reldword_m64_rsi(file, cur):
    """
    48 89 b5
    """
    x = unpack("<i", file.read(4))[0]
    ret = 'mov qword [rbp'
    if x > 0:
        ret += '+' + hex(x)
    elif x < 0:
        ret += '-' + hex(-x)
    ret += '], rsi'
    return ret

def mov_rbp_relbyte_m64_rax(file, cur):
    """
    48 89 45
    """
    x = unpack("<b", file.read(1))[0]
    ret = 'mov qword [rbp'
    if x > 0:
        ret += '+' + hex(x)
    elif x < 0:
        ret += '-' + hex(-x)
    ret += '], rax'
    return ret

x64_mov_r_qword_rel_rbp = {
    b'\x45': ('rax', '<b', 1),
    b'\x4d': ('rcx', '<b', 1),
    b'\x55': ('rdx', '<b', 1),
    b'\x5d': ('rbx', '<b', 1),
    b'\x75': ('rsi', '<b', 1),
    b'\x85': ('rsi', '<i', 4),
}
def mov_r64_rbp_rel_m64(file, cur):
    """
    48 8b RR
    For RR, see above dict
    """
    reg = x64_mov_r_qword_rel_rbp[cur[2].to_bytes(1, 'little')]
    x = unpack(reg[1], file.read(reg[2]))[0]
    ret = f'mov {reg[0]}, qword [rbp'
    if x > 0:
        ret += '+' + hex(x)
    elif x < 0:
        ret += '-' + hex(-x)
    ret += ']'
    return ret
for key, value in x64_mov_r_qword_rel_rbp.items():
    known_instructions[b'\x48\x8b' + key] = mov_r64_rbp_rel_m64

x8_mov_rbp = {
    b'\x45': 'al',
    b'\x4d': 'cl',
    b'\x55': 'dl',
    b'\x5d': 'bl',
}
def mov_rbp_relbyte(file, cur):
    """
    88 RR
    For RR, see above dict
    """
    reg = x8_mov_rbp[cur[1].to_bytes(1, 'little')]
    x = unpack("<b", file.read(1))[0]
    ret = 'mov byte [rbp'
    if x > 0:
        ret += '+' + hex(x)
    elif x < 0:
        ret += '-' + hex(-x)
    ret += '], ' + reg
    return ret
for key, value in x8_mov_rbp.items():
    known_instructions[b'\x88' + key] = mov_rbp_relbyte

x64_mov_mem_reldword_r64_r8 = {
    b'\x90': ('rax', 'dl'),
    b'\x8a': ('rdx', 'cl'),
}
def mov_mem_reldword_r64_r8(file, cur):
    """
    88 RR
    """
    regs = x64_mov_mem_reldword_r64_r8[cur[1].to_bytes(1, 'little')]
    x = unpack("<i", file.read(4))[0]
    ret = f'mov byte [{regs[0]}'
    if x > 0:
        ret += '+' + hex(x)
    elif x < 0:
        ret += '-' + hex(-x)
    ret += f'], {regs[1]}'
    return ret
for opcode, reg in x64_mov_mem_reldword_r64_r8.items():
    known_instructions[b'\x88' + opcode] = mov_mem_reldword_r64_r8

def mov_mem_reldword_rdx_al(file, cur):
    """
    88 82
    """
    x = unpack("<i", file.read(4))[0]
    ret = 'mov byte [rdx'
    if x > 0:
        ret += '+' + hex(x)
    elif x < 0:
        ret += '-' + hex(-x)
    ret += '], al'
    return ret
known_instructions[b'\x88\x82'] = mov_mem_reldword_rdx_al

def mov_byte_rdx_al(file, cur):
    """
    88 02
    """
    return 'mov byte[rdx], al'
known_instructions[b'\x88\x02'] = mov_byte_rdx_al

def mov_rbp_relbyte_dx(file, cur):
    """
    66 89 55
    """
    x = unpack("<b", file.read(1))[0]
    ret = 'mov word [rbp'
    if x > 0:
        ret += '+' + hex(x)
    elif x < 0:
        ret += '-' + hex(-x)
    ret += '], dx'
    return ret
known_instructions[b'\x66\x89\x55'] = mov_rbp_relbyte_dx

def mov_word_rdx_ax(file, cur):
    """
    66 89 02
    """
    return 'mov word [rdx], ax'
known_instructions[b'\x66\x89\x02'] = mov_word_rdx_ax

x32_movzx_r64 = {
    b'\x40': ('eax', 'rax'),
    b'\x45': ('eax', 'rbp'),
    b'\x4d': ('ecx', 'rbp'),
    b'\x55': ('edx', 'rbp'),
    b'\x5d': ('ebx', 'rbp'),
}
def movzx_r32_r64_relbyte_m8(file, cur):
    """
    0f b6 RR
    For RR, see above dict
    """
    reg = x32_movzx_r64[cur[2].to_bytes(1, 'little')]
    x = unpack("<b", file.read(1))[0]
    ret = f'movzx {reg[0]}, byte [{reg[1]}'
    if x > 0:
        ret += '+' + hex(x)
    elif x < 0:
        ret += '-' + hex(-x)
    ret += ']'
    return ret
for key, value in x32_movzx_r64.items():
    known_instructions[b'\x0f\xb6' + key] = movzx_r32_r64_relbyte_m8

def movzx_eax_mem_rdx_plus_rax(file, cur):
    """
    0f b6 04 02
    """
    return 'movzx eax, byte [rdx+rax]'
known_instructions[b'\x0f\xb6\x04\x02'] = movzx_eax_mem_rdx_plus_rax

def movzx_eax_mem_rdx_plus_rax_plus_dword_offset(file, cur):
    """
    0f b6 84 02
    """
    x = unpack("<i", file.read(4))[0]
    ret = 'movzx eax, byte [rdx+rax'
    if x > 0:
        ret += '+' + hex(x)
    elif x < 0:
        ret += '-' + hex(-x)
    ret += ']'
    return ret
known_instructions[b'\x0f\xb6\x84\x02'] = movzx_eax_mem_rdx_plus_rax_plus_dword_offset

def movzx_mem_rdx_plus_rax_plus_dword_offset_cl(file, cur):
    """
    88 8c 02
    """
    x = unpack("<i", file.read(4))[0]
    ret = 'movzx byte [rdx+rax'
    if x > 0:
        ret += '+' + hex(x)
    elif x < 0:
        ret += '-' + hex(-x)
    ret += '], cl'
    return ret
known_instructions[b'\x88\x8c\x02'] = movzx_mem_rdx_plus_rax_plus_dword_offset_cl

def movzx_eax_rbp_reldword_m8(file, cur):
    """
    0f b6 80
    """
    x = unpack("<i", file.read(4))[0]
    ret = 'movzx eax, byte [rbp'
    if x > 0:
        ret += '+' + hex(x)
    elif x < 0:
        ret += '-' + hex(-x)
    ret += ']'
    return ret
known_instructions[b'\x0f\xb6\x80'] = movzx_eax_rbp_reldword_m8

def movzx_ecx_rbp_reldword_rcx(file, cur):
    """
    0f b6 89
    """
    x = unpack("<i", file.read(4))[0]
    ret = 'movzx ecx, byte [rcx'
    if x > 0:
        ret += '+' + hex(x)
    elif x < 0:
        ret += '-' + hex(-x)
    ret += ']'
    return ret
known_instructions[b'\x0f\xb6\x89'] = movzx_ecx_rbp_reldword_rcx

x8_movzx_eax = {
    b'\xc0': 'eax, al',
    b'\xc8': 'ecx, al',
    b'\xc9': 'ecx, cl',
    b'\xd0': 'edx, al',
    b'\xd8': 'ebx, al',
    b'\xf0': 'esi, al',
    b'\xf8': 'edi, al',
}
def movzx_r32_r8(file, cur):
    """
    0f b6 RR
    For RR see above dict
    """
    reg = x8_movzx_eax[cur[2].to_bytes(1, 'little')]
    return f'movzx {reg}'
for key, value in x8_movzx_eax.items():
    known_instructions[b'\x0f\xb6' + key] = movzx_r32_r8

x8H_movzx_eax = {
    b'\xc0': 'r8d, al',
    b'\xc8': 'r9d, al',
}
def movzx_Hr32_r8(file, cur):
    """
    44 0f b6 RR
    For RR see above dict
    """
    reg = x8H_movzx_eax[cur[3].to_bytes(1, 'little')]
    return f'movzx {reg}'
for key, value in x8H_movzx_eax.items():
    known_instructions[b'\x44\x0f\xb6' + key] = movzx_Hr32_r8

def movzx_edx_word_ptr_rax(file, cur):
    """
    0f b7 10
    """
    return 'movzx edx, word [rax]'
known_instructions[b'\x0f\xb7\x10'] = movzx_edx_word_ptr_rax

def movsxd_rdx_eax(file, cur):
    """
    48 63 d0
    """
    return 'movsxd rdx, eax'
known_instructions[b'\x48\x63\xd0'] = movsxd_rdx_eax

def or_r64_r64(file, cur):
    """
    48 09 RR
    """
    regs = x64_r_r[cur[2].to_bytes(1, 'little')]
    return f'or {regs}'
for opcode, reg in x64_r_r.items():
    known_instructions[b'\x48\x09' + opcode] = or_r64_r64

def or_eax_imm8(file, cur):
    """
    83 c8
    """
    x = unpack("<b", file.read(1))[0]
    return f'or eax, {hex(x)}'
known_instructions[b'\x83\xc8'] = or_eax_imm8

def shl_r64_imm8(file, cur):
    """
    48 c1 RR
    """
    reg = x64_shl_r_imm8[cur[2].to_bytes(1, 'little')]
    x = unpack("<B", file.read(1))[0]
    return f'shl {reg}, {x}'
for opcode, reg in x64_shl_r_imm8.items():
    known_instructions[b'\x48\xc1' + opcode] = shl_r64_imm8

def sub_r32_r32(file, cur):
    """
    29
    """
    reg = file.read(1)
    return 'sub ' + x86_r_r[reg]
known_instructions[b'\x29'] = sub_r32_r32

def test_r64_r64(file, cur):
    """
    48 85
    """
    return 'test ' + x64_r_r[file.read(1)]
known_instructions[b'\x48\x85'] = test_r64_r64

def test_r32_r32(file, cur):
    """
    85
    """
    return 'test ' + x86_r_r[file.read(1)]
known_instructions[b'\x85'] = test_r32_r32

def test_al_al(file, cur):
    """
    84 c0
    """
    return 'test al, al'
known_instructions[b'\x84\xc0'] = test_al_al

def call_rax(file, cur):
    """
    ff d0
    """
    return 'call rax'
known_instructions[b'\xff\xd0'] = call_rax

def call_rel_rip_imm32(file, cur):
    """
    ff 15
    """
    x = unpack('<i', file.read(4))[0]
    return f'call [{hex(x+file.tell())}]'
known_instructions[b'\xff\x15'] = call_rel_rip_imm32

def call_rel_imm32(file, cur):
    """
    e8
    """
    x = unpack('<i', file.read(4))[0]
    return f'call {hex(x+file.tell())}'
known_instructions[b'\xe8'] = call_rel_imm32

def ret(file, cur):
    """
    c3
    """
    return 'ret'
known_instructions[b'\xc3'] = ret

def padding(file, cur):
    """
    00
    """
    return '1 byte padding'
known_instructions[b'\x00'] = padding

def push_rel_rip(file, cur):
    """
    ff 35
    """
    x = unpack('<i', file.read(4))[0]
    return f'push qword [{hex(x+file.tell())}]'
known_instructions[b'\xff\x35'] = push_rel_rip

def bnd_jmp_rel_rip(file, cur):
    """
    f2 ff 25
    """
    x = unpack('<i', file.read(4))[0]
    return f'bnd jmp qword [{hex(x+file.tell())}]'
known_instructions[b'\xf2\xff\x25'] = bnd_jmp_rel_rip

def bnd_jmp_rel_imm32(file, cur):
    """
    f2 e9
    """
    x = unpack('<i', file.read(4))[0]
    return f'bnd jmp qword [{hex(x+file.tell())}]'
known_instructions[b'\xf2\xe9'] = bnd_jmp_rel_imm32

def nop(file, cur):
    """
    90          simple nop
    0f 1f 00    nop DWORD PTR [rax]
    0f 1f 44 00 00  nop DWORD PTR [rax+rax*1+0x0]
    """
    return 'nop'
known_instructions[b'\x90'] = nop
known_instructions[b'\x0f\x1f\x00'] = nop
known_instructions[b'\x0f\x1f\x44\x00\x00'] = nop

def push_imm32(file, cur):
    """
    68
    """
    x = unpack('<i', file.read(4))[0]
    return f'push {hex(x)}'
known_instructions[b'\x68'] = push_imm32

def xor_r32_r32(file, cur):
    """
    31
    """
    return 'xor ' + x86_r_r[file.read(1)]
known_instructions[b'\x31'] = xor_r32_r32

def pop_r(file, cur):
    """
    Many versions, see x64_pop_r
    """
    return 'pop ' + x64_pop_r[cur]
for key, value in x64_pop_r.items():
    known_instructions[key] = pop_r

def push_r(file, cur):
    """
    Many versions, see x64_pop_r
    """
    return 'push ' + x64_push_r[cur]
for key, value in x64_push_r.items():
    known_instructions[key] = push_r

def lea_r8_rel_imm32(file, cur):
    """
    4c 8d 05
    """
    x = unpack('<i', file.read(4))[0]
    return f'lea r8, [{hex(x+file.tell())}]'
known_instructions[b'\x4c\x8d\x05'] = lea_r8_rel_imm32

x64_lea_rel = {
    b'\x05': ('rax', 'rip'),
    b'\x0d': ('rcx', 'rip'),
    b'\x15': ('rdx', 'rip'),
    b'\x35': ('rsi', 'rip'),
    b'\x3d': ('rdi', 'rip'),
    b'\x85': ('rax', 'rbp'),
    b'\x90': ('rdx', 'rax'),
    b'\x95': ('rdx', 'rbp'),
    b'\xb1': ('rsi', 'rcx'),
}
def lea_r64_rel_imm32(file, cur):
    """
    48 8d
    """
    reg = file.read(1)
    x = unpack('<i', file.read(4))[0]
    regs = x64_lea_rel[reg]
    if regs[1] == 'rip':
        return f'lea {regs[0]}, [{hex(x+file.tell())}]'
    else:
        if x > 0:
            return f'lea {regs[0]}, [{regs[1]}+{hex(x)}]'
        else:
            return f'lea {regs[0]}, [{regs[1]}-{hex(-x)}]'
known_instructions[b'\x48\x8d'] = lea_r64_rel_imm32

x86_lea_r32_rax_plus_byteoffset = {
    b'\x50': 'edx',
    b'\x48': 'ecx',
}
def lea_r32_rax_plus_byteoffset(file, cur):
    """
    8d RR
    """
    reg = x86_lea_r32_rax_plus_byteoffset[cur[1].to_bytes(1, 'little')]
    x = unpack('<b', file.read(1))[0]
    ret = f'lea edx, [{reg}'
    if x > 0:
        ret += '+' + hex(x)
    elif x < 0:
        ret += '-' + hex(-x)
    ret += ']'
    return ret
for opcode, reg in x86_lea_r32_rax_plus_byteoffset.items():
    known_instructions[b'\x8d' + opcode] = lea_r32_rax_plus_byteoffset

def hlt(file, cur):
    """
    f4
    """
    return 'hlt'
known_instructions[b'\xf4'] = hlt

def mov_rax_qword_fs_0x28(file, cur):
    """
    64 48 8b 04 25 28 00 00 00
    """
    return 'mov rax, stack_canary (qword fs:0x28)'
known_instructions[b'\x64\x48\x8b\x04\x25\x28\x00\x00\x00'] = mov_rax_qword_fs_0x28

def rep_stos_qword_es_rdi_rax(file, cur):
    """
    f3 48 ab
    """
    return 'rep stos qword es:[rdi], rax'
known_instructions[b'\xf3\x48\xab'] = rep_stos_qword_es_rdi_rax