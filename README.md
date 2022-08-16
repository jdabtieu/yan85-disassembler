# yan85 disassembler
Decompiles basic yan85 VM instructions into x64-like NASM Assembly.

This disassembler does not work for the "full yan85" levels. A disassembler for that is being worked on.

## List of valid challenges
- babyrev 12.0
- babyrev 12.1
- babyrev 13.0
- babyrev 13.1
- babyrev 14.0
- babyrev 14.1
- babyrev 15.0
- babyrev 15.1

# Issues
This disassembler also disassembles some x64 instructions, to figure out the stripped binaries (challenges ending in .1).

It only contains the opcodes necessary to disassemble the provided binaries, and does not contain the full x64 opcode library. Trying to use this disassembler for non-yan85 binaries will probably not work. That being said, since gcc and the challenges can be updated, it may introduce instructions that the disassembler doesn't know how to handle or sneaks past the function filters. If any of these happen:
- You get a fatal error while disassembling
- The registers / jumps make no sense (e.g. `mov yip, yflags`)
- There are significant chunks of native x64 instructions in `execute_program` and functions marked as `unknown unknown(unknown unknown...)`

Please submit an issue in the Issue tab, along with the full traceback if printed and the binary (`objdump -M intel -d` of the binary works too)

# Cheating?
If you work at ASU and would like me to take down this repo, please submit an issue stating so and I will remove it.
