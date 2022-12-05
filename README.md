# yan85 tools
- Disassembler: disassembles yan85 VM instructions into x64-like NASM Assembly
- Debugger: Provides a gdb-peda like basic debugger for debugging yan85 assembly files
- Assembler: Assembles yan85 assembly into bytecode (no jumps)

The disassembler supports both the "basic" and "full" yan85 emulation levels, in the babyrev series of the F2021 Archive dojo. Specifically, it can disassemble levels 12.0-18.1, inclusive. For levels 19.0 and 19.1, only the assembler will be helpful. For the new dojo, there are more challenges where this tool may be useful.

Yan85 shows up again in the toddlerone series. The executable format is a bit different, and I didn't bother to update the disassembler to support it. However, the assembler will still do your bidding for these levels (except yan85_64).

Decompiler Usage: `python[3] yan85decompile.py [-h] [-d dumpfile] [-i] filename`<br>
Use the `-d` flag to dump the randomized components into an asmfile for debugging and assembly purposes.<br>
Use the `-i` flag for levels where you have to supply yan85 code to be run. If you fail to specify this flag, disassembly will fail with an unknown instruction error.

Debugger Usage: `python[3] yandb.py asm_filename`

Assembler Usage: `python[3] yanas.py [-h] [-o file] filename`
Use the `-o` flag to output the bytecode to a file, otherwise, write to stdout.

# Issues
This disassembler also disassembles some x64 instructions, to figure out the stripped binaries (challenges ending in .1).

It only contains the opcodes necessary to disassemble the provided binaries, and does not contain the full x64 opcode library. Trying to use this disassembler for non-yan85 binaries will probably not work. That being said, since gcc and the challenges can be updated, it may introduce instructions that the disassembler doesn't know how to handle or sneaks past the function filters. If any of these happen:
- You get a fatal error while disassembling
- The registers / jumps make no sense (e.g. `mov yip, yflags`)
- There are significant chunks of native x64 instructions in `execute_program` and functions marked as `unknown unknown(unknown unknown...)`

The assembler doesn't support jumps at this time, because it's not required for any of the babyrev challenges. This may be added in the future.

Please submit an issue in the Issue tab, along with the full traceback if printed and either the binary or a objdump of it (`objdump -M intel -d`)

# The yan85 architecture
The architecture does not specify an exact bit/byte offset for registers and flags, so the ~~very evil~~ problem setters randomize these offsets between different challenges, meaning that they need to be manually located in each binary. In addition, even the opcodes themselves are not fixed, meaning that depending on the challenge, opcodes can be in the order `[arg1][inst][arg2]`, or something else, like `[arg2][inst][arg1]`.
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

### Undocumented Instructions
These are instructions not included by the yan85 emulators, but are available in the debugger for quality of life purposes. It is not available in the assembler.
| Name      | Description                                                                                                                                                                                                                                                                                           | x64 Equivalent                                                                              | Param 1     | Param 2  |
|-----------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------|-------------|----------|
| sub       | Subtracts the src register from the dst register                                                                                                                                                                                                                                                                | sub dst, src                                                                     | r8 (dst)    | r8 (src) |

# Assembly File
The disassembler generates assembly code, which can optionally be pasted into an assembly file. Right after the line `[i] VM_code_len: XXX`, the assembly code will start.

Assembly format:
- One instruction per line
- NASM syntax, for compatibility with "basic" yan85 levels, a `Y_` prefix must be added to all instructions (e.g. `Y_mov`)
- Labels (and addresses) at the start of a line are ignored
- Comments begin with a `;`
- All jumps are absolute (e.g. `jne 0x51`)
- To specify starting memory, put `.MEMORY` at the start of a line, followed by a space, followed by up to 256 hex bytes (e.g. `.MEMORY 0001afbdee`). This is used in the debugger only.
- All other directives (`.REGISTER, .FLAG, .SYSCALL, .INST, .ABI`) are in the format `.DIRECTIVE name value`. These are used in the assembler only.

A sample assembly file is in [sample.asm](sample.asm)
