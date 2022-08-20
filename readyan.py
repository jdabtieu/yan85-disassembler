from struct import unpack

from lib_func import *

def disassemble_full(cur_func, VM_code, VM_code_len, file):
    # Sections loaded into mem at file offset+0x1000
    VM_code -= 0x1000
    VM_code_len -= 0x1000
    print(f'[i] VM_code    @ {hex(VM_code)}')
    print(f'[i] VM_code_len@ {hex(VM_code_len)}')
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
        inst = VM_inst[mcode[1]]
        if inst == 'interpret_imm':
            dst = VM_regs[mcode[0]]
            imm8 = mcode[2]
            if dst != 'yip':
                print(f'Y_mov {dst}, {hex(imm8)}')
            else:
                print(f'Y_jmp {hex(imm8)}')
            continue
        if inst == 'interpret_add':
            dst = VM_regs[mcode[0]]
            src = VM_regs[mcode[2]]
            print(f'Y_add {dst}, {src}')
            continue
        if inst == 'interpret_stk':
            if mcode[0] == 0: # push only
                src = VM_regs[mcode[2]]
                print(f'Y_push {src}')
            elif mcode[2] == 0: # pop only
                dst = VM_regs[mcode[0]]
                print(f'Y_pop {dst}')
            else: # mov
                src = VM_regs[mcode[2]]
                dst = VM_regs[mcode[0]]
                print(f'Y_mov {dst}, {src}')
            continue
        if inst == 'interpret_sys':
            sys_id = VM_syscalls[mcode[0]]
            if sys_id == 'sys_exit':
                print(f'Y_sys [sys_exit]')
            else:
                r8 = VM_regs[mcode[2]]
                print(f'Y_sys [{sys_id}] --> {r8}')
            continue
        if inst == 'interpret_stm':
            dst = VM_regs[mcode[0]]
            src = VM_regs[mcode[2]]
            print(f'Y_mov byte [{dst}], {src}')
            continue
        if inst == 'interpret_ldm':
            dst = VM_regs[mcode[0]]
            src = VM_regs[mcode[2]]
            print(f'Y_mov {dst}, byte [{src}]')
            continue
        if inst == 'interpret_cmp':
            dst = VM_regs[mcode[0]]
            src = VM_regs[mcode[2]]
            print(f'Y_cmp {dst}, {src}')
            continue
        if inst == 'interpret_jmp':
            mask = VM_jumps[mcode[0]]
            r8 = VM_regs[mcode[2]]
            print(f'Y_{mask} {r8}')
            continue
        raise NotImplementedError(inst)