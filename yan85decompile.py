import argparse
import os
import sys
import subprocess

from readyan import disassemble_full, get_opcode_layout
from instructions import known_instructions
from lib_func import *
import lib_func

parser = argparse.ArgumentParser(description="yan85 disassembler")
parser.add_argument("-d", help="Dump randomized flags, registers, syscalls, instructions, opcodes to file. Only available for full yan85", metavar="dumpfile")
parser.add_argument("-i", help="This yan85 program reads code from the user instead of from the binary. Full yan85 is assumed", action="store_true")
parser.add_argument("filename")
args = parser.parse_args()

f = open(args.filename, "rb")
dumpfile = open(args.d, "w") if args.d else open(os.devnull, "w")

cur = b""
cur_func = []
well_known_funcs = {}
skip_to = find_libc_funcs(f, well_known_funcs)
# find_libc_funcs(f, well_known_funcs)
# skip_to = int(input("Enter hex addr of first VM func: "), 16) # 0x1000
f.seek(skip_to)
start = skip_to
cur_func_start = start
while True:
  cur += f.read(1)
  if cur in known_instructions:
    # Determine the current instruction
    try:
        res = known_instructions[cur](f, cur)
        if res is None:
            raise Exception()
    except Exception:
        print("Fatal decoding error at: " + hex(start))
        import traceback
        traceback.print_exc()
        sys.exit(1)
    
    # Start a new function if we see endbr64
    if res.startswith('endbr64'):
        if len(cur_func) > 0 and cur_func[0][1] != 0:
            print("unknown unknown(unknown unknown...):")
        for inst in cur_func:
            print(hex(inst[1]).rjust(8) + ": " + inst[0])
        cur_func = []
        cur_func_start = f.tell() - 4
    
    # Attempt to find the calling function names
    res = replace_addr_with_func_name(res, well_known_funcs)
    # Add the current instruction to the current function
    cur_func.append((res, start))
    
    # Try to find well known functions
    res, seek = find_well_known_funcs(cur_func, cur_func_start, well_known_funcs, f)
    if res and seek is not None:
        f.seek(seek)
    cur = b""
    start = f.tell()
    # Found VM_code, time to disassemble
    if lib_func.VM_code != -1:
        print("[i] Detected: Full yan85 emulation")
        disassemble_full(cur_func, lib_func.VM_code, lib_func.VM_code_len, lib_func.VM_mem, f)
        sys.exit(0)
    # Found execute_program, time to disassemble
    if "execute_program" in well_known_funcs:
        print("[i] Detected: Basic yan85 emulation")
        break
    # Reached end of VM, time to exit
    if args.i and "interpreter_loop" in well_known_funcs:
        print("[i] End of VM.")
        get_opcode_layout()
        sys.exit(0)
  if len(cur) > 10:
    print(f"Aborting: unrecognized instruction at offset {hex(f.tell()-len(cur))}")
    for inst in cur_func:
        print(hex(inst[1]).rjust(8) + ": " + inst[0])
    sys.exit(1)

stk = []
for inst in cur_func:
    if inst[0] == 'call interpret_imm':
        setup = stk[-4:]
        if (setup[0][0].startswith("mov rax, qword") and
            setup[1][0].startswith("mov edx,") and
            setup[2][0].startswith("mov esi,") and
            setup[3][0] == "mov rdi, rax"):
                stk.pop()
                stk.pop()
                stk.pop()
                stk.pop()
                rdx = setup[1][0].split(", ")[1]
                rsi = VM_regs[int(setup[2][0].split(", ")[1], 16)]
                stk.append((f"Y_mov {rsi}, {rdx}", setup[0][1]))
                continue
    if inst[0] == 'call interpret_add':
        setup = stk[-4:]
        if (setup[0][0].startswith("mov rax, qword") and
            setup[1][0].startswith("mov edx,") and
            setup[2][0].startswith("mov esi,") and
            setup[3][0] == "mov rdi, rax"):
                stk.pop()
                stk.pop()
                stk.pop()
                stk.pop()
                rdx = VM_regs[int(setup[1][0].split(", ")[1], 16)]
                rsi = VM_regs[int(setup[2][0].split(", ")[1], 16)]
                stk.append((f"Y_add {rsi}, {rdx}", setup[0][1]))
                continue
    if inst[0] == 'call interpret_stm':
        setup = stk[-4:]
        if (setup[0][0].startswith("mov rax, qword") and
            setup[1][0].startswith("mov edx,") and
            setup[2][0].startswith("mov esi,") and
            setup[3][0] == "mov rdi, rax"):
                stk.pop()
                stk.pop()
                stk.pop()
                stk.pop()
                rdx = VM_regs[int(setup[1][0].split(", ")[1], 16)]
                rsi = VM_regs[int(setup[2][0].split(", ")[1], 16)]
                stk.append((f"Y_mov byte[{rsi}], {rdx}", setup[0][1]))
                continue
    if inst[0] == 'call interpret_ldm':
        setup = stk[-4:]
        if (setup[0][0].startswith("mov rax, qword") and
            setup[1][0].startswith("mov edx,") and
            setup[2][0].startswith("mov esi,") and
            setup[3][0] == "mov rdi, rax"):
                stk.pop()
                stk.pop()
                stk.pop()
                stk.pop()
                rdx = VM_regs[int(setup[1][0].split(", ")[1], 16)]
                rsi = VM_regs[int(setup[2][0].split(", ")[1], 16)]
                stk.append((f"Y_mov {rsi}, byte [{rdx}]", setup[0][1]))
                continue
    if inst[0] == 'call interpret_cmp':
        setup = stk[-4:]
        if (setup[0][0].startswith("mov rax, qword") and
            setup[1][0].startswith("mov edx,") and
            setup[2][0].startswith("mov esi,") and
            setup[3][0] == "mov rdi, rax"):
                stk.pop()
                stk.pop()
                stk.pop()
                stk.pop()
                rdx = VM_regs[int(setup[1][0].split(", ")[1], 16)]
                rsi = VM_regs[int(setup[2][0].split(", ")[1], 16)]
                stk.append((f"Y_cmp {rsi}, {rdx}", setup[0][1]))
                continue
    if inst[0].startswith("jne "):
        setup = stk[-5:]
        if (setup[0][0].startswith("mov rax, qword") and
            setup[1][0] == "movzx eax, byte [rbp+0x106]" and
            setup[2][0] == "movzx eax, al" and
            setup[3][0].startswith("and eax,") and
            setup[4][0] == "test eax, eax"):
                stk.pop()
                stk.pop()
                stk.pop()
                stk.pop()
                stk.pop()
                cond = VM_jumps[int(setup[3][0][9:])]
                loc = inst[0].split(" ")[1]
                stk.append((f"Y_{cond} {loc}", setup[0][1]))
                continue
    if inst[0] == 'call interpret_sys':
        setup = stk[-4:]
        if (setup[0][0].startswith("mov rax, qword") and
            setup[1][0].startswith("mov edx,") and
            setup[2][0].startswith("mov esi,") and
            setup[3][0] == "mov rdi, rax"):
                stk.pop()
                stk.pop()
                stk.pop()
                stk.pop()
                rdx = VM_regs[int(setup[1][0].split(", ")[1], 16)]
                rsi = VM_syscalls[int(setup[2][0].split(", ")[1], 16)]
                stk.append((f"Y_syscall [{rsi}] --> {rdx}", setup[0][1]))
                continue
    stk.append(inst)

for inst in stk:
    print(hex(inst[1]).rjust(8) + ": " + inst[0])