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
from util import *
from binary_metadata import BinaryMetadata

# This should be called after the header has been written
def write_sections(hm, in_fh, out_fh, funcs, all_funcs, ordered_funcs):
	# Write the remaining data between text and the header
	in_fh.seek(hm.header_metadata.textoffset)
	diff = 0

	out_fh.write(in_fh.read(out_fh.tell() - hm.header_metadata.textoffset))
	first_func = all_funcs[ordered_funcs[0]]
	out_fh.write(in_fh.read(out_fh.tell() - first_func[ADDR]))

	ba = bytearray(hm.TEXT_orig)

	# Adjust functions
	for i in xrange(0, len(ordered_funcs)):
		if ordered_funcs[i] in funcs:
			continue
		offset = all_funcs[ordered_funcs[i]][ADDR] - hm.header_metadata.textoffset
		size = all_funcs[ordered_funcs[i]][SIZE]
		if offset + size > hm.header_metadata.textsize:
			break
		out_fh.write(hm.code_mangler.adjust_fn(all_funcs[ordered_funcs[i]], hm.TEXT_orig[offset:(offset + size)], hm.header_metadata.textvmaddr, hm.text_pad, hm.header_metadata.dataoff, hm.header_metadata.stubsoff, funcs, all_funcs))

	out_fh.write(hm.code_mangler.get_pad(hm.text_pad))

	stubsoff = hm.header_metadata.stubsoff - hm.header_metadata.textoffset
	diff += (stubsoff - hm.header_metadata.textsize)
	out_fh.write(hm.TEXT_orig[hm.header_metadata.textsize:stubsoff])

	# Adjust stubs
	stubs = hm.TEXT_orig[stubsoff:(stubsoff + hm.header_metadata.stubssize)]
	out_fh.write(hm.code_mangler.adjust_stubs(stubs, hm.header_metadata.textvmaddr, hm.header_metadata.stubsoff, hm.total_fn_size))

	shoff = hm.header_metadata.shoff - hm.header_metadata.textoffset
	start = hm.header_metadata.textsize + hm.header_metadata.stubssize + diff
	out_fh.write(hm.TEXT_orig[start:shoff])

	# Adjust stub helper
	stub_helper = hm.TEXT_orig[shoff:(shoff + hm.header_metadata.shsize)]
	out_fh.write(hm.code_mangler.adjust_stub_helper(stub_helper, hm.header_metadata.textvmaddr, hm.header_metadata.shoff, hm.total_fn_size))

	out_fh.write(hm.TEXT_orig[(shoff + hm.header_metadata.shsize):])

	# zero padding to assure the __text region fits in one or more pages exactly
	out_fh.write(bytearray(hm.zero_pad))

	in_fh.seek(hm.header_metadata.textoffset + len(hm.TEXT_orig))

	out_fh.write(in_fh.read(hm.header_metadata.dataoff - in_fh.tell()))

	in_fh.seek(hm.header_metadata.dataoff)

	out_fh.write(in_fh.read(hm.header_metadata.nlsymoff - in_fh.tell()))
	nldata = in_fh.read(hm.header_metadata.nlsymsize)
	out_fh.write(hm.adjust_nl_pointers(nldata, hm.total_fn_size))

	out_fh.write(in_fh.read(hm.header_metadata.lasymoff - in_fh.tell()))
	ladata = in_fh.read(hm.header_metadata.lasymsize)
	out_fh.write(hm.adjust_la_pointers(ladata, hm.total_fn_size))

	# write the other regions until we hit the function starts
	out_fh.write(in_fh.read(hm.header_metadata.function_starts_offset - in_fh.tell()))
	out_fh.write(hm.header_metadata.funcs_start_data)
	in_fh.seek(in_fh.tell() + len(hm.header_metadata.funcs_start_data))

	# write the new function starts region
	out_fh.write(in_fh.read(hm.header_metadata.symoff - in_fh.tell()))

	# write the new symtable
	for sym in hm.header_metadata.nlists:
		if hm.binary_class == CLASS_MACHO:
	 		swap_nlist32_file(sym[0]).to_fileobj(out_fh)
	 	else:
	 		swap_nlist64_file(sym[0]).to_fileobj(out_fh)

	# read and write the rest of the file (dysymtable, string table etc.)
	in_fh.seek(hm.header_metadata.symoff + hm.header_metadata.symsize)
	out_fh.write(in_fh.read())

def write_sections_nops(hm, in_fh, out_fh, funcs, all_funcs):
	in_fh.seek(hm.header_metadata.textoffset)

	total_nops_bytes = 0

	out_fh.write(in_fh.read())
	for func in funcs:
		out_fh.seek(all_funcs[func][ADDR])
		out_fh.write(hm.code_mangler.get_nops(all_funcs[func][SIZE]))
		total_nops_bytes += all_funcs[func][SIZE]

	if hm.verbose:
		print "nop'd {} bytes".format(total_nops_bytes)

def usage():
	sys.stderr.write("Usage: python r2_test.py <path_to_binary_file> -a <analysis> [-v]\n\n")
	sys.stderr.write("-a <analysis>:	The analysis parameter is used to determine which type of analysis is to be\n"
		"performed on the given binary (this tells the program what fucntions to look for when considering\n"
		"their possible elimination from the binary)\n")
	sys.stderr.write("Current analyses:\n")
	sys.stderr.write("framework_database\n")
	sys.stderr.write("uncalled_functions\n")

def main(argc, argv):
	logging.basicConfig(level = logging.INFO)
	strategy = STRATEGY_REMOVE
	verbose = False

	if len(argv) == 5:
		if argv[4] == "-v":
			verbose = True

	if argv[3] == "framework_database":
		bm = BinaryMetadata(argv[1], ANALYSIS_TYPE_FRAMEWORK_DATABASE, verbose)
		strategy = STRATEGY_NOPS
	else:
		bm = BinaryMetadata(argv[1], ANALYSIS_TYPE_UNCALLED_FUNCS, verbose)

	hm = HeaderMangler(bm.binary_class, bm.arch, argv[1], strategy, verbose)
	
	finfo = bm.get_func_info()

	if verbose and strategy != STRATEGY_NOPS:
		print "Will remove functions: " + str(finfo[0])
	hm.remove_funcs(finfo[0], finfo[1], finfo[2])
	if strategy == STRATEGY_REMOVE:
		write_sections(hm, hm.fh, hm.out_fh, finfo[0], finfo[1], finfo[2])
	else:
		write_sections_nops(hm, hm.fh, hm.out_fh, finfo[0], finfo[1])

	if verbose:
		print "Generated debloated file: " + hm.out_fh.name

	hm.out_fh.close()
	bm.cleanup()

if __name__ == "__main__":
	if len(sys.argv) < 3:
		usage()
	else:
		main(len(sys.argv), sys.argv)
