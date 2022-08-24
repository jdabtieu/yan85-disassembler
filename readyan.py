from struct import unpack
import sys

from lib_func import *
import lib_func

# default
_OP = 1
_A1 = 0
_A2 = 2

def get_opcode_layout():
    import yan85decompile
    func = lib_func.VM_interpret_imm
    ptr = 0
    for i in range(len(func)):
        if func[i][0] == "call write_register":
            ptr = i
            break
    # Did not find write_register
    if i == len(func):
        print("[!] Unable to autodetect opcode layout: x86_call")
        sys.exit(1)
    for i in range(ptr - 1, -1, -1):
        if not func[i][0].startswith("mov"):
            ptr = i + 1
            break
    # Did not find first mov/movzx
    if i == 0:
        print("[!] Unable to autodetect opcode layout: x86_endbr64")
        sys.exit(1)
    regs = {"rax": "", "rbx": "", "rcx": "", "rdx": "", "rsi": "", "rdi": ""}
    rmap = {"rax": "rax", "rbx": "rbx", "rcx": "rcx", "rdx": "rdx", "rsi": "rsi", "rdi": "rdi",
            "eax": "rax", "ebx": "rbx", "ecx": "rcx", "edx": "rdx", "esi": "rsi", "edi": "rdi",
            "al":  "rax", "bl":  "rbx", "cl":  "rcx", "dl":  "rdx", "sil": "rsi", "dil": "rdi"}
    while True:
        if func[ptr][0] == 'call write_register': break
        args = [x.strip() for x in func[ptr][0].split(" ", 1)[1].split(",")]
        if args[0] not in rmap: # mov m, r
            ptr += 1
            continue
        if args[0] in rmap and args[1] in rmap: # mov r, r
            regs[rmap[args[0]]] = regs[rmap[args[1]]]
        elif args[0] in rmap: # mov r, stuff
            regs[rmap[args[0]]] = args[1]
        else:
            print("[!] Unable to autodetect opcode layout: x86_mov")
        ptr += 1
    global _A1
    global _A2
    global _OP
    _A1 = (0x10 - int(regs["rsi"].split("rbp-")[1][:-1], 16) % 0x10) % 0x10
    _A2 = (0x10 - int(regs["rdx"].split("rbp-")[1][:-1], 16) % 0x10) % 0x10
    _OP = 3 - _A1 - _A2
    print("[i] In every 3 bytes of yancode:")
    print(f"[i] Byte {_OP} = opcode")
    print(f"[i] Byte {_A1} = arg1")
    print(f"[i] Byte {_A2} = arg2")
    yan85decompile.dumpfile.write(f'.ABI OP {_OP}\n')
    yan85decompile.dumpfile.write(f'.ABI ARG1 {_A1}\n')
    yan85decompile.dumpfile.write(f'.ABI ARG2 {_A2}\n')

def disassemble_full(cur_func, VM_code, VM_code_len, VM_mem, file):
    get_opcode_layout()
    # Sections loaded into mem at file offset+0x1000
    VM_code -= 0x1000
    VM_code_len -= 0x1000
    VM_mem -= 0x1000
    print(f'[i] VM_code    @ {hex(VM_code)}')
    print(f'[i] VM_code_len@ {hex(VM_code_len)}')
    print(f'[i] VM_mem     @ {hex(VM_mem)}')
    file.seek(VM_code_len)
    
    # Get VM_code_len
    VM_code_len = unpack("<I", file.read(4))[0]
    print(f'[i] VM_code_len: {VM_code_len}')
    assert VM_code_len % 3 == 0, 'VM_code_len should be a multiple of 3'
    # Jump to code
    file.seek(VM_code)
    for i in range(0, VM_code_len, 3):
        print(hex(i//3).rjust(8) + ": ", end='')
        mcode = file.read(3)
        inst = VM_inst[mcode[_OP]]
        if inst == 'interpret_imm':
            dst = VM_regs[mcode[_A1]]
            imm8 = mcode[_A2]
            if dst != 'yip':
                print(f'Y_mov {dst}, {hex(imm8)}')
            else:
                print(f'Y_jmp {hex(imm8)}')
            continue
        if inst == 'interpret_add':
            dst = VM_regs[mcode[_A1]]
            src = VM_regs[mcode[_A2]]
            print(f'Y_add {dst}, {src}')
            continue
        if inst == 'interpret_stk':
            if mcode[_A1] == 0: # push only
                src = VM_regs[mcode[_A2]]
                print(f'Y_push {src}')
            elif mcode[_A2] == 0: # pop only
                dst = VM_regs[mcode[_A1]]
                print(f'Y_pop {dst}')
            else: # mov
                src = VM_regs[mcode[_A2]]
                dst = VM_regs[mcode[_A1]]
                print(f'Y_mov {dst}, {src}')
            continue
        if inst == 'interpret_sys':
            sys_id = VM_syscalls[mcode[_A1]]
            if sys_id == 'sys_exit':
                print(f'Y_sys [sys_exit]')
            else:
                r8 = VM_regs[mcode[_A2]]
                print(f'Y_sys [{sys_id}] --> {r8}')
            continue
        if inst == 'interpret_stm':
            dst = VM_regs[mcode[_A1]]
            src = VM_regs[mcode[_A2]]
            print(f'Y_mov byte [{dst}], {src}')
            continue
        if inst == 'interpret_ldm':
            dst = VM_regs[mcode[_A1]]
            src = VM_regs[mcode[_A2]]
            print(f'Y_mov {dst}, byte [{src}]')
            continue
        if inst == 'interpret_cmp':
            dst = VM_regs[mcode[_A1]]
            src = VM_regs[mcode[_A2]]
            print(f'Y_cmp {dst}, {src}')
            continue
        if inst == 'interpret_jmp':
            mask = VM_jumps[mcode[_A1]]
            r8 = VM_regs[mcode[_A2]]
            print(f'Y_{mask} {r8}')
            continue
        raise NotImplementedError(inst)
    
    # Read memory if defined
    data_sect = lib_func.elf['SECTIONS']['.data']
    if VM_mem >= data_sect[0] and VM_mem <= data_sect[0] + data_sect[1]:
        file.seek(VM_mem)
        print('.MEMORY ' + file.read(0x100).hex())