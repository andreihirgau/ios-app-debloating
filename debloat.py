import r2pipe
import sys
import os
from header_mangler import HeaderMangler
from macholib.MachOStandalone import MachOStandalone
from macholib.MachO import MachO
from macholib.util import strip_files
import machobot.dylib as dylib
from machobot.common.macho_helpers import modify_macho_file_headers
from macholib.mach_o import *
from keystone import *
from capstone import *

def usage():
	sys.stderr.write("Usage: python r2_test.py <path_to_binary_file> [<function_name>]\n")

NOP_CODE = b"NOP"

ADDR=0
SIZE=1
NAME=2

def main(argc, argv):
	hm = HeaderMangler(argv[1])
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
		elif len(funcs) == 1:
			hm.remove_func(argv[1], funcs[0][NAME].replace('sym.', ''), int(funcs[0][ADDR], 0), int(funcs[0][SIZE], 0))
			#replace_with_nops(funcs[0], argv[1], argv[1] + ".nop", len(argv) - 3)
		else:
			sys.stderr.write("Couldn't find a matching function for " + argv[2] + "\n")
	r2.quit()

if __name__ == "__main__":
	if len(sys.argv) < 2:
		usage()
	else:
		main(len(sys.argv), sys.argv)
		#dump_whole(sys.argv[1])

