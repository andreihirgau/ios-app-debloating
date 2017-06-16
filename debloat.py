import sys
import os
import logging
import uncalled_functions_analysis
import framework_database_analysis
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
	sys.stderr.write("Usage: python r2_test.py <path_to_binary_file> -a <analysis>\n\n")
	sys.stderr.write("-a <analysis>:	The analysis parameter is used to determine which type of analysis is to be\n"
		"performed on the given binary (this tells the program what fucntions to look for when considering\n"
		"their possible elimination from the binary)\n")
	sys.stderr.write("Current analyses:\n")
	sys.stderr.write("framework_database\n")
	sys.stderr.write("uncalled_functions\n")

def main(argc, argv):
	logging.basicConfig(level = logging.INFO)

	if argv[3] == "framework_database":
		bm = BinaryMetadata(argv[1], ANALYSIS_TYPE_FRAMEWORK_DATABASE)
	else:
		bm = BinaryMetadata(argv[1])

	hm = HeaderMangler(bm.binary_class, bm.arch, argv[1])
	
	finfo = bm.get_func_info()
	print finfo[0]
	hm.remove_funcs(finfo[0], finfo[1], finfo[2])

	bm.cleanup()

if __name__ == "__main__":
	if len(sys.argv) < 3:
		usage()
	else:
		main(len(sys.argv), sys.argv)
