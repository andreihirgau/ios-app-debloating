import r2pipe
import sys
import os
from header_mangler import *
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

def main(argc, argv):
	all_funcs = {}
	ordered_funcs = []
	info = None
	prev_func = None

	hm = HeaderMangler(argv[1])
	r2 = r2pipe.open(argv[1], ['-B', ' 0x0'])
	r2.cmd('aaa')
	if argc < 3:
		print r2.cmd("afl")
	else:
		results = r2.cmd("afl")
		funcs = []

		for line in results.split("\n"):
			if info is not None:
				end_addr = int(info[0], 0) + int(info[2], 0)
			else:
				end_addr = -1
			info = line.split()
			fname = info[3].replace('sym.', '')

		 	diff = 0 if end_addr == -1 else int(info[0], 0) - end_addr
		 	if prev_func is not None:
		 		all_funcs[prev_func][DIFF] = diff
		 	all_funcs[fname] = [int(info[0], 0), int(info[2], 0), 0, prev_func]
		 	ordered_funcs.append(fname)
		 	prev_func = fname
			for i in xrange(2, argc):
				# TODO do some additional parsing on the function name and avoid "in"
				if argv[i] in line:
					funcs.append(info[3].replace('sym.', ''))

		if len(funcs) == 0:
			sys.stderr.write("Couldn't find matching functions\n")
		else:
			hm.remove_funcs(argv[1], funcs, all_funcs, ordered_funcs)
		
	r2.quit()

if __name__ == "__main__":
	if len(sys.argv) < 2:
		usage()
	else:
		main(len(sys.argv), sys.argv)
