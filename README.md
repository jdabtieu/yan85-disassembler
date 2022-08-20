# yan85 disassembler
Decompiles yan85 VM instructions into x64-like NASM Assembly.

This disassembler supports both the "basic" and "full" yan85 emulation levels, but is only fully tested for the levels listed below.

Usage: `python[3] yan85decompile.py <filename>`

## List of tested and valid challenges
- babyrev 12.0
- babyrev 12.1
- babyrev 13.0
- babyrev 13.1
- babyrev 14.0
- babyrev 14.1
- babyrev 15.0
- babyrev 15.1
- babyrev 16.0

# Issues
This disassembler also disassembles some x64 instructions, to figure out the stripped binaries (challenges ending in .1).

It only contains the opcodes necessary to disassemble the provided binaries, and does not contain the full x64 opcode library. Trying to use this disassembler for non-yan85 binaries will probably not work. That being said, since gcc and the challenges can be updated, it may introduce instructions that the disassembler doesn't know how to handle or sneaks past the function filters. If any of these happen:
- You get a fatal error while disassembling
- The registers / jumps make no sense (e.g. `mov yip, yflags`)
- There are significant chunks of native x64 instructions in `execute_program` and functions marked as `unknown unknown(unknown unknown...)`

Please submit an issue in the Issue tab, along with the full traceback if printed and the binary (`objdump -M intel -d` of the binary works too)

# Cheating?
If you work at ASU and would like me to take down this repo, please submit an issue stating so and I will remove it.

# The yan85 architecture
The architecture does not specify an exact bit/byte offset for registers and flags, so the ~~very evil~~ problem setters randomize these offsets between different challenges, meaning that they need to be manually located in each binary.
## Registers
yan85 registers are 1 byte long, so for most registers, they can only store byte values. This means that the stack is at most 256 bytes long.
| Binary Name | Name   | Description                             | x64 equivalent |
|-------------|--------|-----------------------------------------|----------------|
| a           | ya     | General purpose register                | rax            |
| b           | yb     | General purpose register                | rbx            |
| c           | yc     | General purpose register                | rcx            |
| d           | yd     | General purpose register                | rdx            |
| s           | ystk   | Stack pointer, offsets are all positive | rsp            |
| i           | yip    | Instruction pointer                     | rip            |
| f           | yflags | Flags register (see Flags section)      | eflags         |

## Flags & Jumps
The yan85 architecture sets 5 flags in each `cmp`. These results can then be used for `jmp`s later on. Unlike x64, flags are not modified by anything except `cmp`.
| Jump Name | Description               |
|-----------|---------------------------|
| jl        | Jump if reg1 < reg2       |
| jg        | Jump if reg1 > reg2       |
| je        | Jump if reg1 == reg2      |
| jne       | Jump if reg1 != reg2      |
| jbz       | Jump if reg1 == reg2 == 0 |

## Instructions
| Name      | Description                                                                                                                                                                                                                                                                                           | x64 Equivalent                                                                              | Param 1     | Param 2  |
|-----------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------|-------------|----------|
| imm       | Moves a byte value to the dst register                                                                                                                                                                                                                                                                | mov dst, imm8                                                                               | r8 (dst)    | imm8     |
| add       | Adds the src register to the dst register                                                                                                                                                                                                                                                             | add dst, src                                                                                | r8 (dst)    | r8 (src) |
| stk       | The stack instruction deals with push and pop. See the below entries.                                                                                                                                                                                                                                 |                                                                                             |             |          |
| _stk_push | Pushes r8 onto the stack                                                                                                                                                                                                                                                                              | push r8                                                                                     | 0           | r8       |
| _stk_pop  | Pops r8 from the stack                                                                                                                                                                                                                                                                                | pop r8                                                                                      | r8          | 0        |
| _stk_mov  | `stk` can perform a push and pop (in that order) in one instruction, so<br>triggering both is equivalent to moving the src register to the dst register                                                                                                                                               | mov dst, src                                                                                | r8 (dst)    | r8 (src) |
| stm       | Moves a byte value from the src register to the memory location pointed<br>to by the dst register                                                                                                                                                                                                     | mov byte [dst], src                                                                         | r8 (dst)    | r8 (src) |
| ldm       | Moves a byte value from the memory location pointed to by the src<br>register to the dst register                                                                                                                                                                                                     | mov dst, byte [src]                                                                         | r8 (dst)    | r8 (src) |
| cmp       | Compares the two registers and sets the yflags register. See the Flags table.                                                                                                                                                                                                                         | cmp r8, r8                                                                                  | r8          | r8       |
| jmp       | The jmp instruction covers every jump in the jump function<br>(jg, jl, je, jne, jbz, jge, jle, jmp). If mask is 0, jump directly to r8.<br>Otherwise, jump directly to r8 only if yflags & mask != 0. For example, to<br>perform a jge, if jg is bit 3 and je is bit 2, the mask would be 0b00000110. |                                                                                             | imm8 (mask) | r8       |
| sys       | Performs a syscall with up to 3 parameters, stored in ra, rb, rc. The syscall<br>performed is the x64 syscall with rax = sys_id, and the return value of the<br>syscall is stored in r8.                                                                                                              | mov eax, sys_id<br>movzx edi, ra<br>movzx esi, rb<br>movzx edx, rc<br>syscall<br>mov r8, al | sys_id      | r8       |
