import argparse
import sys
import re

class Yan85Asm:
    def __init__(self, asmfile):
        self.reg = {}
        self.flag = {}
        self.syscall = {}
        self.inst = {}
        self.prog = []
        self.op = -1
        self.arg1 = -1
        self.arg2 = -1
        for line in asmfile.readlines():
            if line.startswith("."):
                self.parse_directive(line[1:])
                continue
            # Remove comments, starting with ;
            line = re.sub(r";.+$", "", line)
            # Remove empty lines
            if re.sub(r"^\s*$", "", line) == '':
                continue
            # Remove address info, if present
            line = re.sub(r"^\s*.+:\s*", "", line).strip()
            self.prog.append(line)
    
    def parse_directive(self, line):
        tokens = line.split(" ")
        if tokens[0] == "REGISTER":
            self.reg[tokens[1]] = int(tokens[2], 0)
        elif tokens[0] == "FLAG":
            self.flag[tokens[1]] = int(tokens[2], 0)
        elif tokens[0] == "SYSCALL":
            self.syscall[tokens[1]] = int(tokens[2], 0)
        elif tokens[0] == "INST":
            self.inst[tokens[1]] = int(tokens[2], 0)
        elif tokens[0] == "ABI":
            setattr(self, tokens[1].lower(), int(tokens[2], 0))
        else:
            print("Unrecognized directive: " + line)
            sys.exit(-1)
    
    def assemble(self, outfile):
        ret = []
        for inst in self.prog:
            inst = inst.replace("byte [", "byte[").split(" ", 1)
            ret += getattr(self, inst[0])(inst[1])
        outfile.write(bytes(ret))
    
    def Y_mov(self, args):
        args = [x.strip() for x in args.split(",")]
        ret = [0, 0, 0]
        if args[0] in self.reg and re.fullmatch(r"(0x[a-fA-F0-9]+)|(\d+)", args[1]):
            # Y_mov r8, imm8
            ret[self.op] = self.inst["interpret_imm"]
            ret[self.arg1] = self.reg[args[0]]
            ret[self.arg2] = int(args[1], 0)
            return ret
        if args[0] in self.reg and args[1] in self.reg:
            # Y_mov r8, r8
            ret[self.op] = self.inst["interpret_stk"]
            ret[self.arg1] = self.reg[args[0]]
            ret[self.arg2] = self.reg[args[1]]
            return ret
        if args[0].startswith('byte[') and args[1] in self.reg:
            # Y_mov byte [r8], r8
            ret[self.op] = self.inst["interpret_stm"]
            ret[self.arg1] = self.reg[args[0].split("[")[1].split("]")[0]]
            ret[self.arg2] = self.reg[args[1]]
            return ret
        if args[1].startswith('byte[') and args[0] in self.reg:
            # Y_mov r8, byte [r8]
            ret[self.op] = self.inst["interpret_ldm"]
            ret[self.arg1] = self.reg[args[0]]
            ret[self.arg2] = self.reg[args[1].split("[")[1].split("]")[0]]
            return ret
        print("Unrecognized instruction: Y_mov " + str(args))
        sys.exit(-1)
        
    def Y_add(self, args):
        args = [x.strip() for x in args.split(",")]
        ret = [0, 0, 0]
        if args[0] in self.reg and args[1] in self.reg:
            # Y_add r8, r8
            ret[self.op] = self.inst["interpret_add"]
            ret[self.arg1] = self.reg[args[0]]
            ret[self.arg2] = self.reg[args[1]]
            return ret
        print("Unrecognized instruction: Y_add " + str(args))
        sys.exit(-1)
    
    def Y_push(self, args):
        args = [x.strip() for x in args.split(",")]
        ret = [0, 0, 0]
        if args[0] in self.reg:
            ret[self.op] = self.inst["interpret_stk"]
            ret[self.arg1] = 0
            ret[self.arg2] = self.reg[args[0]]
            return ret
        print("Unrecognized instruction: Y_push " + str(args))
        sys.exit(-1)
    
    def Y_pop(self, args):
        args = [x.strip() for x in args.split(",")]
        ret = [0, 0, 0]
        if args[0] in self.reg:
            ret[self.op] = self.inst["interpret_stk"]
            ret[self.arg1] = self.reg[args[0]]
            ret[self.arg2] = 0
            return ret
        print("Unrecognized instruction: Y_pop " + str(args))
        sys.exit(-1)
    
    def Y_cmp(self, args):
        args = [x.strip() for x in args.split(",")]
        ret = [0, 0, 0]
        if args[0] not in self.reg or args[1] not in self.reg:
            print("Unrecognized instruction: Y_cmp " + str(args))
            sys.exit(-1)
        # Y_cmp r8, r8
        ret[self.op] = self.inst["interpret_cmp"]
        ret[self.arg1] = self.reg[args[0]]
        ret[self.arg2] = self.reg[args[1]]
        return ret
    
    def Y_sys(self, args):
        ret = [0, 0, 0]
        sys_name = args.split("[")[1].split("]")[0][4:]
        if sys_name == "exit":
            ret[self.op] = self.inst["interpret_sys"]
            ret[self.arg1] = self.syscall[sys_name]
            ret[self.arg2] = self.reg["ya"] # doesn't matter anyways
            return ret
        dst = args.split("-->")[1].strip()
        if dst not in self.reg:
            print("Unrecognized instruction: Y_sys " + str(args))
            sys.exit(-1)
        ret[self.op] = self.inst["interpret_sys"]
        ret[self.arg1] = self.syscall[sys_name]
        ret[self.arg2] = self.reg[dst]
        return ret

parser = argparse.ArgumentParser(description="yan85 assembler")
parser.add_argument("-o", help="File to store assembled yancode at. If not included, output to stdout", metavar="file")
parser.add_argument("filename")
args = parser.parse_args()

asmfile = open(args.filename, "r")
outfile = open(args.o, "wb") if args.o else sys.stdout.buffer

assembler = Yan85Asm(asmfile)
assembler.assemble(outfile)
