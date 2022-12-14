import re
from struct import unpack
import sys


"""
Ways to fingerprint a function
1. Number of instructions (less reliable)
1b. Heuristic length (e.g. <= 32)
2. Sequence of calls
3. First X instructions (less reliable)
"""
def find_well_known_funcs(cur_func, cur_func_start, well_known_funcs, file):
    import yan85decompile
    calls = []
    for inst in cur_func:
        if inst[0].startswith("call"):
            calls.append(inst[0].split(" ")[1])
    # _start + main
    for i in range(1):
        if len(cur_func) != 12:
            break
        exp = ["endbr64", "xor", "mov", "pop", "mov", "and", "push", "push", "lea", "lea", "lea", "call"]
        found = True
        for i in range(12):
            if not cur_func[i][0].startswith(exp[i]):
                found = False
                break
        if not found:
            break
        # Found _start, find main
        well_known_funcs['_start'] = cur_func_start
        well_known_funcs[cur_func_start] = '_start'
        print('[i] Function _start: ' + hex(cur_func_start))
        for ip in cur_func:
            inst = ip[0]
            if inst.startswith("lea rdi, "):
                off = int(inst.split("[")[1][:-1], 16)
                # Found main
                well_known_funcs['main'] = off
                well_known_funcs[off] = 'main'
                # Skip rest of _start, deregister_tm_clones, register_tm_clones, __do_global_dtors_aux
                queue = list(file.read(4))
                while queue != [0xf3, 0x0f, 0x1e, 0xfa]:
                    queue.pop(0)
                    queue.append(unpack('<B', file.read(1))[0])
                queue = list(file.read(4))
                while queue != [0xf3, 0x0f, 0x1e, 0xfa]:
                    queue.pop(0)
                    queue.append(unpack('<B', file.read(1))[0])
                file.seek(file.tell()-4)
                cur_func.clear()
                return True, None
    
    # void crash(char *msg)
    for i in range(1):
        if len(cur_func) != 12:
            break
        exp = ["endbr64", "push", "mov", "sub", "mov", "mov", "mov", "lea", "mov", "call", "mov", "call"]
        found = True
        for i in range(12):
            if not cur_func[i][0].startswith(exp[i]):
                found = False
                break
        if not found:
            break
        well_known_funcs['crash'] = cur_func_start
        well_known_funcs[cur_func_start] = 'crash'
        print('[i] Function VM_crash: ' + hex(cur_func_start))
        cur_func.clear()
        return True, None
    
    # char *describe_register(byte id)
    for i in range(1):
        if len(cur_func) != 40:
            break
        exp = ["endbr64", "push", "mov", "mov", "mov", "cmp", "jne", "lea", "jmp", "cmp", "jne", "lea"]
        found = True
        for i in range(12):
            if not cur_func[i][0].startswith(exp[i]):
                found = False
                break
        if cur_func[-1][0] != 'ret': break
        if not found:
            break
        well_known_funcs['describe_register'] = cur_func_start
        well_known_funcs[cur_func_start] = 'describe_register'
        print('[i] Function describe_register: ' + hex(cur_func_start))
        cur_func.clear()
        return True, None
        
    # byte read_register(byte REGISTER_ID)
    for i in range(1):
        if len(cur_func) != 46:
            break
        exp = ["endbr64", "push", "mov", "sub", "mov", "mov", "mov", "cmp", "jne", "mov", "movzx", "jmp"]
        found = True
        for i in range(12):
            if not cur_func[i][0].startswith(exp[i]):
                found = False
                break
        if cur_func[-1][0] != 'ret': break
        if not found:
            break
        well_known_funcs['read_register'] = cur_func_start
        well_known_funcs[cur_func_start] = 'read_register'
        print('[i] Function read_register: ' + hex(cur_func_start))
        cur_func.clear()
        return True, None
    
    # void write_register(byte REGISTER_ID, byte val)
    for i in range(1):
        if len(cur_func) != 56:
            break
        exp = ["endbr64", "push", "mov", "sub", "mov", "mov", "mov", "mov", "mov", "mov", "cmp", "jne"]
        found = True
        for i in range(12):
            if not cur_func[i][0].startswith(exp[i]):
                found = False
                break
        if cur_func[-1][0] != 'ret': break
        if not found:
            break
        
        # Get REGISTER_IDs
        i = 0
        regs = ["ya", "yb", "yc", "yd", "ystk", "yip", "yflags"]
        for inst in cur_func:
            if inst[0].startswith("cmp byte [rbp"):
                VM_regs[int(inst[0].split(",")[1], 16)] = regs[i]
                print(f'[i] {inst[0].split(",")[1].strip()}: {regs[i]}')
                yan85decompile.dumpfile.write(f'.REGISTER {regs[i]} {inst[0].split(",")[1].strip()}\n')
                i += 1
        
        # Back to normal decoding
        well_known_funcs['write_register'] = cur_func_start
        well_known_funcs[cur_func_start] = 'write_register'
        print('[i] Function write_register: ' + hex(cur_func_start))
        cur_func.clear()
        return True, None
        
    # byte read_memory(byte addr)
    for i in range(1):
        if len(cur_func) != 12:
            break
        exp = ["endbr64", "push", "mov", "mov", "mov", "mov", "movzx", "mov", "cdqe", "movzx", "pop", "ret"]
        found = True
        for i in range(12):
            if not cur_func[i][0].startswith(exp[i]):
                found = False
                break
        if not found:
            break
        well_known_funcs['read_memory'] = cur_func_start
        well_known_funcs[cur_func_start] = 'read_memory'
        print('[i] Function read_memory: ' + hex(cur_func_start))
        cur_func.clear()
        return True, None
        
    # void write_memory(byte addr, byte val)
    for i in range(1):
        if len(cur_func) != 17:
            break
        exp = ["endbr64", "push", "mov", "mov", "mov", "mov", "mov", "mov", "mov", "movzx", "mov", "cdqe"]
        found = True
        for i in range(12):
            if not cur_func[i][0].startswith(exp[i]):
                found = False
                break
        if cur_func[-1][0] != 'ret': break
        if not found:
            break
        well_known_funcs['write_memory'] = cur_func_start
        well_known_funcs[cur_func_start] = 'write_memory'
        print('[i] Function write_memory: ' + hex(cur_func_start))
        cur_func.clear()
        return True, None
    
    # void interpret_imm(byte REGISTER_ID, byte val)
    for i in range(1):
        if len(cur_func) > 32:
            break
        if len(calls) < 1 or len(calls) > 3: break
        # V1: call describe_register, printf@plt, write_register
        # V2: call write_register
        if calls[-1] != "write_register":
            break
        if "read_register" in calls or "read_memory" in calls or "write_memory" in calls:
            break
        if cur_func[-1][0] != 'ret': break
        global VM_interpret_imm # important for getting opcodes
        VM_interpret_imm = cur_func.copy()
        well_known_funcs['interpret_imm'] = cur_func_start
        well_known_funcs[cur_func_start] = 'interpret_imm'
        print('void interpret_imm(byte REGISTER_ID, byte val):')
        cur_func.clear()
        cur_func.append(('write_register(REGISTER_ID, val);', 0))
        cur_func.append(('return;\n', 0))
        return True, None
    
    
    # void interpret_add(byte REGISTER_ID1, byte REGISTER_ID2)
    for i in range(1):
        if len(cur_func) > 48 or len(cur_func) < 30:
            break
        if len(calls) != 3 and len(calls) != 6: break
        # V1: describe_r*2, printf, read_r*2, write_r
        # V2: read_r*2, write_r
        if calls[-1] != "write_register" or calls[-2] != "read_register" or calls[-3] != "read_register":
            break
        if "read_memory" in calls or "write_memory" in calls:
            break
        if cur_func[-1][0] != 'ret': break
        well_known_funcs['interpret_add'] = cur_func_start
        well_known_funcs[cur_func_start] = 'interpret_add'
        print('void interpret_add(byte REGISTER_ID1, byte REGISTER_ID2):')
        cur_func.clear()
        cur_func.append(('reg1 <-- REGISTER_ID1', 0))
        cur_func.append(('reg2 <-- REGISTER_ID2', 0))
        cur_func.append(('$reg1 += $reg2; AKA', 0))
        cur_func.append(('add reg1, reg2\n', 0))
        return True, None
    
    # void interpret_stk(byte REGISTER_ID1, byte REGISTER_ID2)
    for i in range(1):
        if len(cur_func) < 50 or len(cur_func) > 88:
            break
        if len(calls) != 11 and len(calls) != 4: break
        # V1: desc*2, printf, desc, printf, read_r, write_m, desc, printf, read_m, write_r
        # V2: read_r, write_m, read_m, write_r
        queue = ["read_register", "write_memory", "read_memory", "write_register"]
        i = 0
        valid = True
        for call in calls:
            if i >= len(queue):
                valid = False
                break
            if call == queue[i]:
                i += 1
        if not valid or i != len(queue):
            break
        if cur_func[-1][0] != 'ret': break
        well_known_funcs['interpret_stk'] = cur_func_start
        well_known_funcs[cur_func_start] = 'interpret_stk'
        print('void interpret_stk(byte REGISTER_ID1, byte REGISTER_ID2):')
        cur_func.clear()
        cur_func.append(('reg1 <-- REGISTER_ID1', 0))
        cur_func.append(('reg2 <-- REGISTER_ID2', 0))
        cur_func.append(('if reg2 != NULL:  push reg2', 0))
        cur_func.append(('if reg1 != NULL:  pop reg1\n', 0))
        return True, None
        
    # void interpret_stm(byte REGISTER_ID1, byte REGISTER_ID2)
    for i in range(1):
        if len(cur_func) < 30 or len(cur_func) > 48:
            break
        if len(calls) != 6 and len(calls) != 3: break
        # V1: desc*2, printf, read_r*2, write_m
        # V2: read_r*2, write_m
        if "read_memory" in calls or "write_register" in calls:
            break
        if len(calls) == 6 and calls[3:] != ["read_register", "read_register", "write_memory"]:
            break
        if len(calls) == 3 and calls != ["read_register", "read_register", "write_memory"]:
            break
        if cur_func[-1][0] != 'ret': break
        well_known_funcs['interpret_stm'] = cur_func_start
        well_known_funcs[cur_func_start] = 'interpret_stm'
        print('void interpret_stm(byte REGISTER_ID1, byte REGISTER_ID2):')
        cur_func.clear()
        cur_func.append(('reg1 <-- REGISTER_ID1', 0))
        cur_func.append(('reg2 <-- REGISTER_ID2', 0))
        cur_func.append(('mov byte [reg1], reg2\n', 0))
        return True, None
    
    # void interpret_ldm(byte REGISTER_ID1, byte REGISTER_ID2)
    for i in range(1):
        if len(cur_func) < 26 or len(cur_func) > 48:
            break
        if len(calls) != 6 and len(calls) != 3: break
        # V1: desc*2, printf, read_r, read_m, write_m
        # V2: read_r, read_m, write_m
        if "write_memory" in calls:
            break
        if len(calls) == 6 and calls[3:] != ["read_register", "read_memory", "write_register"]:
            break
        if len(calls) == 3 and calls != ["read_register", "read_memory", "write_register"]:
            break
        if cur_func[-1][0] != 'ret': break
        well_known_funcs['interpret_ldm'] = cur_func_start
        well_known_funcs[cur_func_start] = 'interpret_ldm'
        print('void interpret_ldm(byte REGISTER_ID1, byte REGISTER_ID2):')
        cur_func.clear()
        cur_func.append(('reg1 <-- REGISTER_ID1', 0))
        cur_func.append(('reg2 <-- REGISTER_ID2', 0))
        cur_func.append(('mov reg1, byte [reg2]\n', 0))
        return True, None
    
    # void interpret_cmp(byte REGISTER_ID1, byte REGISTER_ID2)
    for i in range(1):
        if len(cur_func) < 70 or len(cur_func) > 90:
            break
        if len(calls) != 5 and len(calls) != 2: break
        # V1: desc*2, printf, read_r*2
        # V2: read_r*2
        if len(calls) == 5 and calls[3:] != ["read_register", "read_register"]:
            break
        if len(calls) == 2 and calls != ["read_register", "read_register"]:
            break
        if cur_func[-1][0] != 'ret': break
        # Determine jmp bits
        for i in range(len(cur_func)):
            if not cur_func[i][0].startswith("cmp"): continue
            for j in range(i, len(cur_func)):
                if cur_func[j][0].startswith("or"):
                    key = int(cur_func[j][0].split(", ")[1], 16)
                    break
            if cur_func[i+1][0].startswith("jae"): # jl
                VM_jumps["jl"] = key
                VM_jumps[key] = "jl"
                yan85decompile.dumpfile.write(f'.FLAG lt {hex(key)}\n')
            elif cur_func[i+1][0].startswith("jbe"): # jg
                VM_jumps["jg"] = key
                VM_jumps[key] = "jg"
                yan85decompile.dumpfile.write(f'.FLAG gt {hex(key)}\n')
            elif cur_func[i+1][0].startswith("jne") and cur_func[i+3][0].startswith("jne"): # jbz
                VM_jumps["jbz"] = key
                VM_jumps[key] = "jbz"
                yan85decompile.dumpfile.write(f'.FLAG bz {hex(key)}\n')
            elif cur_func[i+1][0].startswith("jne") and not cur_func[i-1][0].startswith("jne"): # je
                VM_jumps["je"] = key
                VM_jumps[key] = "je"
                yan85decompile.dumpfile.write(f'.FLAG eq {hex(key)}\n')
            elif cur_func[i+1][0].startswith("jne"): # jbz second cmp
                pass
            elif cur_func[i+1][0].startswith("je"): # jne
                VM_jumps["jne"] = key
                VM_jumps[key] = "jne"
                yan85decompile.dumpfile.write(f'.FLAG ne {hex(key)}\n')
            else: raise Exception("Unknown jump " + cur_func[i+1][0])
        VM_jumps["jge"] = VM_jumps["je"] | VM_jumps["jg"]
        VM_jumps[VM_jumps["je"] | VM_jumps["jg"]] = "jge"
        VM_jumps["jle"] = VM_jumps["je"] | VM_jumps["jl"]
        VM_jumps[VM_jumps["je"] | VM_jumps["jl"]] = "jle"
        VM_jumps[VM_jumps["jg"] | VM_jumps["jl"]] = "jne"
        
        # Back to regular execution
        well_known_funcs['interpret_cmp'] = cur_func_start
        well_known_funcs[cur_func_start] = 'interpret_cmp'
        print('void interpret_cmp(byte REGISTER_ID1, byte REGISTER_ID2):')
        cur_func.clear()
        cur_func.append(('reg1 <-- REGISTER_ID1', 0))
        cur_func.append(('reg2 <-- REGISTER_ID2', 0))
        for key, value in VM_jumps.items():
            if type(key) == int:
                cur_func.append((f'yflags[{hex(key)}] = {value}', 0))
        cur_func.append(('\n', 0))
        return True, None
    
    # void interpret_jmp(byte trigger_flags, byte REGISTER_ID)
    for i in range(1):
        if len(cur_func) < 24 or len(cur_func) > 50:
            break
        if len(calls) != 6 and len(calls) != 1: break
        # V1: desc*2, printf, puts, read_r, puts
        # V2: read_r
        if len(calls) == 6 and calls[4:] != ["read_register", "puts"]:
            break
        if len(calls) == 1 and calls != ["read_register"]:
            break
        if cur_func[-1][0] != 'ret': break
        well_known_funcs['interpret_jmp'] = cur_func_start
        well_known_funcs[cur_func_start] = 'interpret_jmp'
        print('void interpret_jmp(byte trigger_flags, byte REGISTER_ID):')
        cur_func.clear()
        cur_func.append(('reg <-- REGISTER_ID', 0))
        cur_func.append(('if trigger_flags ==  0: jmp reg', 0))
        cur_func.append(('other trigger_flags   : see interpret_cmp\n', 0))
        return True, None
    
    # void interpret_sys(byte SYSCALL_ID, byte RESULT_REGISTER)
    for i in range(1):
        if len(cur_func) < 132:
            break
        if 'open' not in calls or 'read' not in calls or 'write' not in calls or 'exit' not in calls:
            break
        if cur_func[-1][0] != 'ret': break
        well_known_funcs['interpret_sys'] = cur_func_start
        well_known_funcs[cur_func_start] = 'interpret_sys'
        print('void interpret_sys(byte SYSCALL_ID, byte RESULT_REGISTER):')
        asm = cur_func.copy()
        cur_func.clear()
        cur_func.append(('yan85 ABI:', 0))
        cur_func.append(('Parameter order: syscall(ra, rb, rc)', 0))
        cur_func.append(('Return into register: RESULT_REGISTER', 0))
        cur_func.append(('Available syscalls:', 0))
        for i in range(len(asm)):
            if asm[i][0] == 'call write_register':
                j = i - 1
                syscall_name = ''
                syscall_num = ''
                while True:
                    if syscall_name == '' and asm[j][0].startswith('call'):
                        syscall_name = asm[j][0].split(' ')[1]
                    if syscall_name != '' and asm[j][0].startswith('and'):
                        syscall_num = asm[j][0].split(',')[1].strip()
                        break
                    j -= 1
                VM_syscalls[int(syscall_num)] = 'sys_' + syscall_name
                cur_func.append((f'{syscall_num}\tsys_{syscall_name}', 0))
                yan85decompile.dumpfile.write(f'.SYSCALL {syscall_name} {syscall_num}\n')
            if asm[i][0] == 'call exit':
                j = i - 1
                while True:
                    if asm[j][0].startswith('and'):
                        syscall_num = asm[j][0].split(',')[1].strip()
                        break
                    j -= 1
                VM_syscalls[int(syscall_num)] = 'sys_exit'
                cur_func.append((f'{syscall_num}\tsys_exit\n', 0))
                yan85decompile.dumpfile.write(f'.SYSCALL exit {syscall_num}\n')
        return True, None
    
    # void interpret_instruction(int inst)
    for i in range(1):
        if len(cur_func) < 78 or len(cur_func) > 120:
            break
        if len(calls) < 8: break
        if ("interpret_imm" not in calls or
            "interpret_add" not in calls or
            "interpret_stk" not in calls or
            "interpret_stm" not in calls or
            "interpret_ldm" not in calls or
            "interpret_cmp" not in calls or
            "interpret_jmp" not in calls or
            "interpret_sys" not in calls):
                break
        if cur_func[-1][0] != 'ret': break
        # Determine keys
        for i in range(len(cur_func)):
            if not cur_func[i][0].startswith("call interpret_"): continue
            for j in range(i - 1, 0, -1):
                if cur_func[j][0].startswith("and"):
                    key = int(cur_func[j][0].split(", ")[1])
                    break
                if cur_func[j][0].startswith("jns"):
                    key = 0x80
                    break
            func_name = cur_func[i][0].split("call ")[1]
            VM_inst[key] = func_name
            VM_inst[func_name] = key
            yan85decompile.dumpfile.write(f'.INST {func_name} {hex(key)}\n')
        
        # Back to regular execution
        well_known_funcs['interpret_instruction'] = cur_func_start
        well_known_funcs[cur_func_start] = 'interpret_instruction'
        print('void interpret_instruction(int inst):')
        cur_func.clear()
        cur_func.append(('[arg2][opcode][arg1] where [] = 8 bits', 0))
        for opcode, name in VM_inst.items():
            if type(opcode) != int:
                continue
            cur_func.append((f"{hex(opcode)}:\t{name}", 0))
        cur_func.append(("\n", 0))
        return True, None
    
    # void execute_program()
    for i in range(1):
        if len(cur_func) < 200:
            break
        if len(calls) < len(cur_func) // 7: break
        if cur_func[-1][0] != 'ret': break
        well_known_funcs['execute_program'] = cur_func_start
        well_known_funcs[cur_func_start] = 'execute_program'
        print('void execute_program():')
        cur_func[0] = (cur_func[0][0], 0)
        return True, None
    
    # void interpreter_loop()
    for i in range(1):
        if len(cur_func) < 28 or len(cur_func) > 38:
            break
        if len(calls) > 2 or len(calls) == 0: break
        if calls[-1] != 'interpret_instruction': break
        if not cur_func[-1][0].startswith('jmp'): break
        well_known_funcs['interpreter_loop'] = cur_func_start
        well_known_funcs[cur_func_start] = 'interpreter_loop'
        print('void interpreter_loop():')
        cur_func.clear()
        cur_func.append(('loops through instructions stored in memory\n', 0))
        return True, None
    
    # int main(int argc, char **argv)
    for i in range(1):
        if len(calls) < 1 or calls[-1] != 'memcpy': break
        if cur_func[-2][0] != 'call memcpy': break
        well_known_funcs['main'] = cur_func_start
        well_known_funcs[cur_func_start] = 'main'
        global VM_code
        global VM_code_len
        global VM_mem
        for i in range(len(cur_func) - 1, 0, -1):
            if VM_code_len != -1 and VM_code != -1: break
            if VM_code == -1 and cur_func[i][0].startswith('lea rsi'):
                VM_code = int(cur_func[i][0].split('[')[1][:-1], 16)
            if VM_code_len == -1 and cur_func[i][0].startswith('mov eax, dword'):
                VM_code_len = int(cur_func[i][0].split('[')[1][:-1], 16)
        VM_mem = int(cur_func[-1][0].split('[')[1][:-1], 16)
        cur_func.clear()
        return True, None
    
    return False, 0

VM_jumps = {0: 'jmp'} # others filled in with interpret_cmp

VM_syscalls = {} # filled in with interpret_sys

VM_regs = {} # filled in with interpret_imm

VM_inst = {} # filled in with interpret_instruction

VM_interpret_imm = {} # find opcode layout, for full emulator

elf = None # the elf file

# filled in with main
VM_code_len = -1
VM_code = -1
VM_mem = -1

def replace_addr_with_func_name(call, well_known_funcs):
    if re.fullmatch('call 0x[0-9a-f]+', call) is None:
        return call
    addr = int(call.split('x')[1], 16)
    if addr in well_known_funcs:
        return 'call ' + well_known_funcs[addr]
    else: return call

def read_until_zero(file):
    res = b''
    while True:
        b = file.read(1)
        if b == b'\x00':
            return res
        res += b

def parse_elf_header(file):
    assert file.read(4) == b'\x7fELF', 'Not an ELF file'
    assert file.read(1) == b'\x02', 'Not 64-bit'
    assert file.read(1) == b'\x01', 'Not little-endian'
    assert file.read(1) == b'\x01', 'Not ELF v1'
    assert file.read(1) == b'\x00', 'Not SystemV ABI'
    file.read(1) # e_ident[EI_ABIVERSION]
    file.read(7) # Padding
    assert file.read(2) == b'\x03\x00', 'Not shared object'
    assert file.read(2) == b'\x3e\x00', 'Not AMD64'
    assert file.read(4) == b'\x01\x00\x00\x00', 'Not ELF v1'
    ENTRY_POINT = unpack("<Q", file.read(8))[0]
    PROGRAM_HDR = unpack("<Q", file.read(8))[0]
    SECTION_HDR = unpack("<Q", file.read(8))[0]
    print(f'[i] Entry Point: {hex(ENTRY_POINT)}')
    print(f'[i] Program Header Table: {hex(PROGRAM_HDR)}')
    print(f'[i] Section Header Table: {hex(SECTION_HDR)}')
    file.read(4) # e_flags
    assert file.read(2) == b'\x40\x00', 'Wrong ELF header size'
    PHR_ENTRY_SZ = unpack("<H", file.read(2))[0]
    PHR_N_ENTRIES = unpack("<H", file.read(2))[0]
    SHR_ENTRY_SZ = unpack("<H", file.read(2))[0]
    SHR_N_ENTRIES = unpack("<H", file.read(2))[0]
    SHR_NAMES_IDX = unpack("<H", file.read(2))[0]
    print(f'[i] Program Header Table: {PHR_N_ENTRIES} entries')
    print(f'[i] Section Header Table: {SHR_N_ENTRIES} entries')
    SHSTRTAB_HDR = SHR_NAMES_IDX * SHR_ENTRY_SZ + SECTION_HDR
    print(f'[i] .shstrtab header: {hex(SHSTRTAB_HDR)}')
    return {
        'ENTRY_POINT': ENTRY_POINT,
        'PROGRAM_HDR': PROGRAM_HDR,
        'SECTION_HDR': SECTION_HDR,
        'PHR_ENTRY_SZ': PHR_ENTRY_SZ,
        'PHR_N_ENTRIES': PHR_N_ENTRIES,
        'SHR_ENTRY_SZ': SHR_ENTRY_SZ,
        'SHR_N_ENTRIES': SHR_N_ENTRIES,
        'SHR_NAMES_IDX': SHR_NAMES_IDX,
        'SHSTRTAB_HDR': SHSTRTAB_HDR,
    }

def find_shstrtab(file, elf):
    file.seek(elf['SHSTRTAB_HDR']+0x18)
    SHSTRTAB = unpack("<Q", file.read(8))[0]
    elf['SHSTRTAB'] = SHSTRTAB
    print(f'[i] .shstrtab: {hex(SHSTRTAB)}')

def find_sections(file, elf):
    file.seek(elf['SECTION_HDR'])
    elf['SECTIONS'] = {}
    for i in range(elf['SHR_N_ENTRIES']):
        SH_NAME_OFF = unpack("<I", file.read(4))[0]
        cur_pos = file.tell()
        file.seek(elf['SHSTRTAB']+SH_NAME_OFF)
        NAME = read_until_zero(file).decode('ascii')
        file.seek(cur_pos)
        file.read(4) # sh_type
        file.read(8) # sh_flags
        MEM_ADDR = unpack("<Q", file.read(8))[0]
        ADDR = unpack("<Q", file.read(8))[0]
        SZ = unpack("<Q", file.read(8))[0]
        file.read(4) # sh_link
        file.read(4) # sh_info
        file.read(8) # sh_addralign
        file.read(8) # sh_entsize
        if len(NAME) < 1: continue
        print(f'[i] Section {NAME}: {hex(ADDR)}')
        elf['SECTIONS'][NAME] = (ADDR, SZ, MEM_ADDR)

def parse_libc_funcs(file, elf, well_known_funcs):
    RELA_PLT = elf['SECTIONS']['.rela.plt']
    file.seek(RELA_PLT[0])
    for i in range(RELA_PLT[1] // 24):
        GOT_ADDR = unpack("<Q", file.read(8))[0]
        DYNSYM_IDX = unpack("<Q", file.read(8))[0] >> 32
        file.read(8)
        cur_pos = file.tell()
        PLT_ADDR = elf['SECTIONS']['.plt.sec'][0] + (GOT_ADDR - elf['SECTIONS']['.got'][2] - 0x18) * 2
        file.seek(elf['SECTIONS']['.dynsym'][0] + 24 * DYNSYM_IDX)
        NAME_OFF = unpack("<I", file.read(4))[0]
        file.seek(elf['SECTIONS']['.dynstr'][0] + NAME_OFF)
        NAME = read_until_zero(file).decode('ascii')
        print(f'[i] Function {NAME}: {hex(PLT_ADDR)}')
        well_known_funcs[NAME] = PLT_ADDR
        well_known_funcs[PLT_ADDR] = NAME
        file.seek(cur_pos)

def find_libc_funcs(file, well_known_funcs):
    global elf
    elf = parse_elf_header(file)
    find_shstrtab(file, elf)
    find_sections(file, elf)
    parse_libc_funcs(file, elf, well_known_funcs)
    return elf['SECTIONS']['.text'][2]