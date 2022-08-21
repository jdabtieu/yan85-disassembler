from ctypes import c_ubyte
import io
import os
import sys
from termcolor import colored
import traceback
import re

class Yan85:
    def __init__(self, asmfile):
        self.init_mem = [0]*0x100
        self.reset()
        self.prog = []
        with open(asmfile, 'r') as f:
            for line in f.readlines():
                if line.startswith(".MEMORY "):
                    line = line.split(" ")[1]
                    for i in range(len(line)//2):
                        self.init_mem[i] = int(line[2*i:2*i+2], 16)
                    continue
                # Remove comments, starting with ;
                line = re.sub(r";.+$", "", line)
                # Remove empty lines
                if re.sub(r"^\s*$", "", line) == '':
                    continue
                # Remove address info, if present
                line = re.sub(r"^\s*.+:\s*", "", line).strip()
                self.prog.append(line)
        self.reset()
    
    def print_data(self):
        print(colored("[----------------------------------registers-----------------------------------]", "blue"))
        for reg, val in self.reg.items():
            print(colored(reg.ljust(4), "green") + ": " + hex(val))
        print(colored("flags", "green") + ":", end='')
        for flag, val in self.flags.items():
            if val:
                print(" " + colored(flag.upper(), "red"), end='')
            else:
                print(" " + colored(flag, "green"), end='')
        print()
        print(colored("[-------------------------------------code-------------------------------------]", "blue"))
        for i in range(max(0, self.reg["yip"]-3), self.reg["yip"]):
            print(hex(i).rjust(8) + ": " + self.prog[i])
        print(hex(self.reg["yip"]).rjust(8) + ": " + colored(self.prog[self.reg["yip"]], "green"))
        for i in range(self.reg["yip"]+1, min(len(self.prog), self.reg["yip"]+4)):
            print(hex(i).rjust(8) + ": " + self.prog[i])
        if self.prog[self.reg["yip"]].startswith("Y_sys"):
            print("Guessed arguments:")
            print("arg1: " + hex(self.reg["ya"]))
            if "sys_write" in self.prog[self.reg["yip"]] and self.reg["ya"] == 1: # write str to stdout
                print("arg2: " + str(self.read_str(self.reg["yb"], self.reg["yc"])))
            else:
                print("arg2: " + hex(self.reg["yb"]))
            print("arg3: " + hex(self.reg["yc"]))
        print(colored("[------------------------------------stack-------------------------------------]", "blue"))
        for i in range(self.reg["ystk"], max(-1, self.reg["ystk"]-8), -1):
            print(hex(i).rjust(8) + ": " + hex(self.mem[i]))
    
    def reset(self):
        self.mem = self.init_mem.copy()
        self.reg = {}
        self.reg["ya"] = 0
        self.reg["yb"] = 0
        self.reg["yc"] = 0
        self.reg["yd"] = 0
        self.reg["ystk"] = 0
        self.reg["yip"] = 0
        self.flags = {"eq": False, "ne": False, "gt": False, "lt": False, "bz": False}
        self.fd = [sys.stdin, sys.stdout.buffer, sys.stderr.buffer]
        self.exited = False
        self.exit_code = 0
    
    def step(self):
        if self.exited:
            return False
        inst = self.prog[self.reg["yip"]]
        inst = inst.replace("byte [", "byte[").split(" ", 1)
        try:
            res = getattr(self, inst[0])(inst[1])
        except:
            print(colored("Exception at " + hex(self.reg["yip"]), "red"))
            traceback.print_exc()
            return False
        for reg, val in self.reg.items(): # normalize
            self.reg[reg] = c_ubyte(val).value
        if not res:
            return False
        self.reg["yip"] += 1
        return True
    
    def read_str(self, loc, lim=5000):
        og_loc = loc
        x = b''
        while self.mem[loc] != 0 and loc - og_loc < lim:
            x += self.mem[loc].to_bytes(1, 'little')
            loc += 1
        return x
    
    def Y_mov(self, args):
        args = [x.strip() for x in args.split(",")]
        if args[0] in self.reg and re.fullmatch(r"(0x[a-fA-F0-9]+)|(\d+)", args[1]):
            # Y_mov r8, imm8
            if args[1].startswith("0x"):
                self.reg[args[0]] = int(args[1], 16)
            else:
                self.reg[args[0]] = int(args[1])
            if args[0] == 'yip': self.reg[args[0]] -= 1
            return True
        if args[0] in self.reg and args[1] in self.reg:
            # Y_mov r8, r8
            self.reg[args[0]] = self.reg[args[1]]
            if args[0] == 'yip': self.reg[args[0]] -= 1
            return True
        if args[0].startswith('byte[') and args[1] in self.reg:
            # Y_mov byte [r8], r8
            dst = args[0].split("[")[1].split("]")[0]
            self.mem[self.reg[dst]] = self.reg[args[1]]
            return True
        if args[1].startswith('byte[') and args[0] in self.reg:
            # Y_mov r8, byte [r8]
            src = args[1].split("[")[1].split("]")[0]
            self.reg[args[0]] = self.mem[self.reg[src]]
            if args[0] == 'yip': self.reg[args[0]] -= 1
            return True
        return False
        
    def Y_add(self, args):
        args = [x.strip() for x in args.split(",")]
        if args[0] in self.reg and args[1] in self.reg:
            # Y_add r8, r8
            self.reg[args[0]] += self.reg[args[1]]
            return True
        return False
    
    # Undocumented but useful
    def Y_sub(self, args):
        args = [x.strip() for x in args.split(",")]
        if args[0] in self.reg and args[1] in self.reg:
            # Y_sub r8, r8
            self.reg[args[0]] -= self.reg[args[1]]
            return True
        return False
    
    def Y_push(self, args):
        args = [x.strip() for x in args.split(",")]
        if args[0] in self.reg:
            self.reg["ystk"] += 1
            self.mem[self.reg["ystk"]] = self.reg[args[0]]
            return True
        return False
    
    def Y_pop(self, args):
        args = [x.strip() for x in args.split(",")]
        if args[0] in self.reg:
            self.reg[args[0]] = self.mem[self.reg["ystk"]]
            self.reg["ystk"] -= 1
            return True
        return False
    
    def Y_cmp(self, args):
        args = [x.strip() for x in args.split(",")]
        if args[0] not in self.reg or args[1] not in self.reg:
            return False
        # Y_cmp r8, r8
        reg1 = self.reg[args[0]]
        reg2 = self.reg[args[1]]
        for key, value in self.flags.items():
            self.flags[key] = False
        if reg1 < reg2:
            self.flags["lt"] = True
        if reg1 > reg2:
            self.flags["gt"] = True
        if reg1 == reg2:
            self.flags["eq"] = True
        else:
            self.flags["ne"] = True
        if reg1 == reg2 and reg1 == 0:
            self.flags["bz"] = True
        return True
    
    def Y_jmp(self, args):
        args = [x.strip() for x in args.split(",")]
        if re.fullmatch(r"(0x[a-fA-F0-9]+)|(\d+)", args[0]):
            # Y_jmp imm8
            if args[0].startswith("0x"):
                self.reg["yip"] = int(args[0], 16) - 1
            else:
                self.reg["yip"] = int(args[0]) - 1
            return True
        if args[0] in self.reg:
            # Y_jmp r8
            self.reg["yip"] = self.reg[args[0]] - 1
            return True
        return False
    
    def Y_jg(self, args):
        args = [x.strip() for x in args.split(",")]
        if args[0] not in self.reg:
            return False
        if self.flags["gt"]:
            self.reg["yip"] = self.reg[args[0]] - 1
        return True
    
    def Y_jge(self, args):
        args = [x.strip() for x in args.split(",")]
        if args[0] not in self.reg:
            return False
        if self.flags["gt"] or self.flags["eq"]:
            self.reg["yip"] = self.reg[args[0]] - 1
        return True
    
    def Y_jl(self, args):
        args = [x.strip() for x in args.split(",")]
        if args[0] not in self.reg:
            return False
        if self.flags["lt"]:
            self.reg["yip"] = self.reg[args[0]] - 1
        return True
    
    def Y_jle(self, args):
        args = [x.strip() for x in args.split(",")]
        if args[0] not in self.reg:
            return False
        if self.flags["lt"] or self.flags["eq"]:
            self.reg["yip"] = self.reg[args[0]] - 1
        return True
    
    def Y_je(self, args):
        args = [x.strip() for x in args.split(",")]
        if args[0] not in self.reg:
            return False
        if self.flags["eq"]:
            self.reg["yip"] = self.reg[args[0]] - 1
        return True
    
    def Y_jne(self, args):
        args = [x.strip() for x in args.split(",")]
        if args[0] not in self.reg:
            return False
        if self.flags["ne"]:
            self.reg["yip"] = self.reg[args[0]] - 1
        return True
    
    def Y_jbz(self, args):
        args = [x.strip() for x in args.split(",")]
        if args[0] not in self.reg:
            return False
        if self.flags["bz"]:
            self.reg["yip"] = self.reg[args[0]] - 1
        return True
    
    def Y_sys(self, args):
        sys_name = args.split("[")[1].split("]")[0]
        if sys_name == "sys_exit":
            self.exit_code = self.reg["ya"]
            self.exited = True
            return True
        dst = args.split("-->")[1].strip()
        if dst not in self.reg:
            return False
        if sys_name == "sys_read":
            fd = self.reg["ya"]
            buf = self.reg["yb"]
            rlen = self.reg["yc"]
            if fd == 0: # stdin
                try:
                    x = input()[:rlen].encode('utf-8')
                except KeyboardInterrupt: # Ctrl+C, is a pause
                    return False
            else:
                x = self.fd[fd].read(rlen)
            for i in range(len(x)):
                self.mem[buf+i] = x[i]
            return True
        if sys_name == "sys_write":
            fd = self.reg["ya"]
            buf = self.reg["yb"]
            rlen = self.reg["yc"]
            self.fd[fd].write(bytes(self.mem[buf:buf+rlen]))
            return True
        if sys_name == "sys_open":
            ptr = self.reg["ya"]
            filename = b''
            while True:
                x = self.mem[ptr]
                if x == b'\x00': break
                filename += x
                ptr += 1
            filename = filename.decode("utf-8")
            if filename == "/flag":
                self.fd.append(io.BytesIO(b"pwn.college{practice}"))
            else:
                self.fd.append(open(filename, 'rb'))
            return True
        return False

os.system("color")
print("yandb v0.1.0 by jdabtieu")
if len(sys.argv) == 2:
    print(f"Loading file {sys.argv[1]}...")
    file = Yan85(sys.argv[1])
    print(f"Loaded file {sys.argv[1]}!")
else:
    print("Usage: python[3] yan85debug.py <filename>")
    sys.exit(-1)
print("Type 'help' for help")
print("Using gdb-peda shorthand syntax")

breaks = set()
prev = ""

def run_continuous():
    # Run until file exits
    while not file.exited:
        # Hit a breakpoint
        if file.reg["yip"] in breaks:
            file.print_data()
            return
        
        # Step
        res = file.step()
        
        # Return if something bad happened
        if not res:
            file.print_data()
            print(colored("FAULT", "red"))
            return

help_msg = """help:     print this help message
exit:     exit yandb
quit:     exit yandb
ni:       next instruction (step)
x/s <addr>:     print the null-terminated string at addr, in hex
exec <code>:    run python in the debugger context
reset:    reset to start of binary
b <addr>: set a breakpoint at addr
r:        reset to start of binary and run until exit, breakpoint, or exception
c:        continue until exit, breakpoint, or exception
info:     print current register/instruction/stack info
starti:   reset to start of binary and start the program"""
while True:
    if file.exited:
        print(f"Program exited with exit code {file.exit_code}")
        
    cmd = input(colored("yandb> ", "red"))
    if cmd == "":
        cmd = prev
    else:
        prev = cmd
    
    # Command processing
    if cmd == "help":
        print(help_msg)
    elif cmd == "\x04" or cmd == "exit" or cmd == "quit":
        sys.exit(0)
    elif cmd == "ni":
        res = file.step()
        file.print_data()
        if not res:
            print(colored("FAULT", "red"))
    elif cmd.startswith("x/s "):
        loc = int(cmd.split("x/s")[1].strip(), 16)
        print(file.read_str(loc))
    elif cmd.startswith("exec "):
        exec(cmd[5:].strip())
    elif cmd == "reset":
        file.reset()
    elif cmd.startswith("b "):
        loc = int(cmd.split("b", 1)[1].strip(), 16)
        print("Added breakpoint at " + hex(loc))
        breaks.add(loc)
    elif cmd == "r":
        file.reset()
        run_continuous()
    elif cmd == "c":
        # gotta pass the breakpoint first
        res = file.step()
        if not res:
            file.print_data()
            print(colored("FAULT", "red"))
        else:
            run_continuous()
    elif cmd == "info":
        file.print_data()
    elif cmd == "starti":
        file.reset()
        file.print_data()
    else:
        print("Unknown command")