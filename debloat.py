import sys
import os
import logging
import analysis
from header_mangler import *
from macholib.MachOStandalone import MachOStandalone
from macholib.MachO import MachO
from macholib.util import strip_files
import machobot.dylib as dylib
from machobot.common.macho_helpers import modify_macho_file_headers
from macholib.mach_o import *
from keystone import *
from capstone import *
from util import LOGGER_NAME
from binary_metadata import BinaryMetadata

def usage():
	sys.stderr.write("Usage: python r2_test.py <path_to_binary_file>\n")

def main(argc, argv):
	logging.basicConfig(level = logging.INFO)

	bm = BinaryMetadata(argv[1])
	hm = HeaderMangler(bm.binary_class, bm.arch, argv[1])
	
	finfo = bm.get_func_info()
	hm.remove_funcs(finfo[0], finfo[1], finfo[2])

	bm.cleanup()

if __name__ == "__main__":
	if len(sys.argv) < 2:
		usage()
	else:
		main(len(sys.argv), sys.argv)
