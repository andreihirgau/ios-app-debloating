import r2pipe
import sys
from keystone import *

def usage():
	sys.stderr.write("Usage: python r2_test.py <path_to_binary_file> [<function_name>]\n")

NOP_CODE = b"NOP"

ADDR=0
SIZE=1
NAME=2

def get_nop(arch, mode, code):
	try:
		ks = Ks(arch, mode)
		encoding, count = ks.asm(code)
		return encoding
	except KsError as e:
		print "ERROR: {}".format(e)

def replace_with_nops(func, inf, outf):
	ifile = open(inf, 'rb')
	ofile = open(outf, 'wb')

	start_addr = func[ADDR]
	ofile.write(ifile.read(int(func[ADDR], 0)))
	nop = get_nop(KS_ARCH_X86, KS_MODE_64, NOP_CODE)

	for i in range(1, int(func[SIZE])):
		ba = bytearray(nop)
		ofile.write(ba)

	ifile.seek(int(func[SIZE], 0) - 1, 1)
	ofile.write(ifile.read())

	ifile.close()
	ofile.close()

def main(argc, argv):
	r2 = r2pipe.open(argv[1], ['-B', ' 0x0'])
	r2.cmd('aa')
	if argc < 3:
		print r2.cmd("afl")
	else:
		results = r2.cmd("afl")
		funcs = []

		for line in results.split("\n"):
			if argv[2] in line:
				info = line.split()
				funcs.append((info[0], info[2], info[3]))

		if len(funcs) > 1:
			print "Found more functions that match {}".format(argv[2])
			for func in funcs:
				print "{} {} {}".format(func[ADDR], func[SIZE], func[NAME])
		else:
			replace_with_nops(funcs[0], argv[1], argv[1] + ".nop")
	r2.quit()

if __name__ == "__main__":
	if len(sys.argv) < 2:
		usage()
	else:
		main(len(sys.argv), sys.argv)

