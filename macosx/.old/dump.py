from capstone import *
import sys

def usage():
	sys.err.write("Usage: python ./dump.py <file> <offset> <size>\n")

def dump(f, offset, dim):
    file = open(f)
    file.seek(int(offset, 0))

    binary = file.read(int(dim, 0))
    mi = Cs(CS_ARCH_X86, CS_MODE_64)
    for i in mi.disasm(binary, 0):
        print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))

if __name__ == "__main__":
	if len(sys.argv) > 3:
		dump(sys.argv[1], sys.argv[2], sys.argv[3])
	else:
		usage()
