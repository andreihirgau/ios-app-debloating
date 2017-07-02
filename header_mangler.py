import os
import sys
from header_metadata import *
from macholib.MachOStandalone import MachOStandalone
from macholib.MachO import MachO
from macholib.util import strip_files
import machobot.dylib as dylib
from machobot.common.macho_helpers import modify_macho_file_headers
from macholib.mach_o import *
from util import *
from x86_64_mangler import *
from arm_mangler import *
from binary_metadata import *

SEC_OFFSET 		= 0
SEC_SIZE 		= 1

STRATEGY_REMOVE = 0
STRATEGY_NOPS 	= 1

def dec_syms(syms, amount):
	if syms - amount < 0:
		return syms
	else:
		return syms - amount

class HeaderMangler(object):
	def __init__(self, binary_class, arch, exec_path, strategy, verbose = False):
		self.path = exec_path
		self.mangled_text_segment = False
		self.header_analyzed = False
		self.shrink_by = 0
		self.header_metadata = None

		self.strategy = strategy
		self.verbose = verbose

		self.fname = None
		self.faddr = 0
		self.fsize = 0
		self.arch = arch
		self.binary_class = binary_class

		self.total_shrink = 0

		self.entry_func = []

		self.total_fn_size = 0
		self.zero_pad = 0
		self.text_pad = 0

		self.TEXT_orig = None
		self.fh = None
		self.out_fh = None

		self.binary_class = binary_class

		if arch == ARCH_ARM:
			self.code_mangler = ARM_Mangler()
		elif arch == ARCH_X86_64:
			self.code_mangler = X86_64_Mangler()
		else:
			raise Exception("Unknown arch: " + arch)

	def analyze_header(self):
		self.macho = MachO(self.path)
		self.header_metadata = HeaderMetadata(self.macho, self.binary_class)
		self.header_metadata.read_tables()
		self.header_analyzed = True

	def write_header(self, fh, total_shrink):
		h = self.macho.headers[0]
		h.size -= total_shrink
		self.macho.write(fh)

	def adjust_nl_pointers(self, nldata, shirnk):
		return nldata

	def adjust_la_pointers(self, ladata, shrink):
		off = 0
		new_ladata = ""
		size = LA_PTR_SIZE_32 if self.binary_class == CLASS_MACHO else LA_PTR_SIZE_64

		while off < len(ladata):
			if self.binary_class == CLASS_MACHO64:
				lptr = la_ptr_64.from_str(ladata[off:(off + size)])
				lptr.ptr = big_swap_u64(lptr.ptr)
				lptr.ptr -= shrink
				lptr.ptr = little_swap_u64(lptr.ptr)
				new_ladata += lptr.to_str()
				off += LA_PTR_SIZE_64
			else:
				lptr = la_ptr_32.from_str(ladata[off:(off + size)])
				lptr.ptr = big_swap_u32(lptr.ptr)
				lptr.ptr -= shrink
				lptr.ptr = little_swap_u32(lptr.ptr)
				new_ladata += lptr.to_str()
				off += LA_PTR_SIZE_32
			
		return new_ladata

	def read_TEXT_segment(self, in_fh):
		in_fh.seek(self.header_metadata.textoffset)
		self.TEXT_orig = in_fh.read(self.header_metadata.TEXTsize - self.header_metadata.textoffset)

	def adjust_symtable(self, fname):
		ntype = 36 if self.binary_class == CLASS_MACHO64 else 15
		return len(self.header_metadata.nlists)
		copy = list(self.header_metadata.nlists)
		for i in xrange(len(copy) - 1, -1, -1):
			if fname in self.header_metadata.nlists[i][1]:
				if self.header_metadata.nlists[i][0].n_type == ntype:
					del self.header_metadata.nlists[i - 1]
					del self.header_metadata.nlists[i - 1]
					del self.header_metadata.nlists[i - 1]
					del self.header_metadata.nlists[i - 1]
					i -= 4
				else:
					del self.header_metadata.nlists[i]
			elif self.header_metadata.nlists[i][0].n_type == ntype and "_" in self.header_metadata.nlists[i][1]:
				self.header_metadata.nlists[i][0].n_value -= self.total_fn_size
				self.header_metadata.nlists[i - 1][0].n_value -= self.total_fn_size
			elif "_main" in self.header_metadata.nlists[i][1]:
				self.header_metadata.nlists[i][0].n_value -= self.total_fn_size
				self.header_metadata.nlists[i - 1][0].n_value -= self.total_fn_size

		return len(self.header_metadata.nlists)

	def adjust_function_starts(self, removed_funcs, all_funcs):
		funcs = self.header_metadata.read_func_starts()
		x = decode_uleb128(funcs[FUNCS_START_BA], 0)
		funcs_ba = bytearray()
		addr = x[ULEB_DATA]
		old_offset = 0
		i = 0
		found = False

		while x[ULEB_OFF] != funcs[FUNCS_START_SIZE]:
			found = False
			for func in removed_funcs:
				if all_funcs[func][ADDR] == addr:
					found = True
					break
			old_offset = x[ULEB_OFF]
			x = decode_uleb128(funcs[FUNCS_START_BA], x[ULEB_OFF])
			addr += x[ULEB_DATA]

			if found:
				pass
				#print "addr: " + hex(x[ULEB_OFF] - old_offset)
				#funcs_ba += bytearray(x[ULEB_OFF] - old_offset)
			else:
				funcs_ba += funcs[FUNCS_START_BA][i:old_offset]
				i = old_offset

		# TODO calculate the function starts and write them
		temp = bytearray()
		for i in xrange(0, len(funcs[FUNCS_START_BA])):
			temp += bytes(0)
		self.header_metadata.funcs_start_data = temp

	def adjust_offset(self, off, symoff, shrink, total_shrink):
		if off <= 0:
			return off
		elif off > symoff:
			return off - total_shrink
		else:
			return off - shrink


	def remove_funcs(self, funcs, all_funcs, ordered_funcs):
		if not self.header_analyzed:
			self.analyze_header()

		self.fh = open(self.path, 'rb')
		self.read_TEXT_segment(self.fh)

		for f in funcs:
			self.remove_func(f, all_funcs[f], all_funcs)

		# after we've made the changes to remove the functions, adjust the load commands
		self.adjust_lcs()
		self.adjust_function_starts(funcs, all_funcs)

		if self.strategy == STRATEGY_REMOVE and self.verbose:
			print "__text size reduced by: " + str(self.total_fn_size + self.total_shrink)

		self.out_fh = open(self.path + "-debloated", 'wb')
		self.write_header(self.out_fh, self.total_shrink)

	def adjust_lcs(self):
		if self.strategy == STRATEGY_NOPS:
			return

		# stubs are in ARM mode (4 bytes / insn) and __text is in thumb mode (2 bytes / insn) 
		# force the alignment of the stubs region to 4 bytes
		if self.arch == ARCH_ARM and self.total_fn_size % 4 != 0:
			self.text_pad = 2
			self.fsize -= self.text_pad
			self.total_fn_size -= self.text_pad
			self.zero_pad -= self.text_pad

		# we can't possibly remove an odd number of bytes from ARM code, so something has gone wrong
		if self.arch == ARCH_ARM:
			assert(self.total_fn_size % 4 == 0)

		segtext = self.header_metadata.sections["__TEXT"]["__TEXT"]
		secttext = self.header_metadata.sections["__TEXT"]["__text"]

		symoff = self.header_metadata.lcs[LC_SYMTAB].symoff

		for segname, _ in self.header_metadata.sections.iteritems():
			for sectname, cmd in self.header_metadata.sections[segname].iteritems():
				if isinstance(cmd, segment_command_64) or isinstance(cmd, segment_command):
					if SEG_DATA in cmd.segname:
						cmd.fileoff -= self.shrink_by
					if SEG_LINKEDIT in cmd.segname:
						cmd.filesize = cmd.filesize - self.total_shrink - self.shrink_by
				elif SEG_TEXT in segname and SECT_TEXT not in cmd.sectname:
					cmd.addr -= self.total_fn_size
					cmd.offset -= self.total_fn_size
				else:
					if cmd.offset > secttext.offset and SEG_TEXT in segname:
						cmd.offset -= self.total_fn_size

		segtext.filesize -= self.shrink_by
		secttext.size -= self.total_fn_size

		self.header_metadata.lcs[LC_DYLD_INFO_ONLY].rebase_off = self.adjust_offset(self.header_metadata.lcs[LC_DYLD_INFO_ONLY].rebase_off, symoff, self.shrink_by, self.total_shrink)
		self.header_metadata.lcs[LC_DYLD_INFO_ONLY].bind_off = self.adjust_offset(self.header_metadata.lcs[LC_DYLD_INFO_ONLY].bind_off, symoff, self.shrink_by, self.total_shrink)
		self.header_metadata.lcs[LC_DYLD_INFO_ONLY].weak_bind_off = self.adjust_offset(self.header_metadata.lcs[LC_DYLD_INFO_ONLY].weak_bind_off, symoff, self.shrink_by, self.total_shrink)
		self.header_metadata.lcs[LC_DYLD_INFO_ONLY].lazy_bind_off = self.adjust_offset(self.header_metadata.lcs[LC_DYLD_INFO_ONLY].lazy_bind_off, symoff, self.shrink_by, self.total_shrink)
		self.header_metadata.lcs[LC_DYLD_INFO_ONLY].export_off = self.adjust_offset(self.header_metadata.lcs[LC_DYLD_INFO_ONLY].export_off, symoff, self.shrink_by, self.total_shrink)

		self.header_metadata.lcs[LC_DYSYMTAB].tocoff = self.adjust_offset(self.header_metadata.lcs[LC_DYSYMTAB].tocoff, symoff, self.shrink_by, self.total_shrink)
		self.header_metadata.lcs[LC_DYSYMTAB].indirectsymoff = self.adjust_offset(self.header_metadata.lcs[LC_DYSYMTAB].indirectsymoff, symoff, self.shrink_by, self.total_shrink)
		self.header_metadata.lcs[LC_DYSYMTAB].modtaboff = self.adjust_offset(self.header_metadata.lcs[LC_DYSYMTAB].modtaboff, symoff, self.shrink_by, self.total_shrink)
		self.header_metadata.lcs[LC_DYSYMTAB].extrefsymoff = self.adjust_offset(self.header_metadata.lcs[LC_DYSYMTAB].extrefsymoff, symoff, self.shrink_by, self.total_shrink)
		self.header_metadata.lcs[LC_DYSYMTAB].extreloff = self.adjust_offset(self.header_metadata.lcs[LC_DYSYMTAB].extreloff, symoff, self.shrink_by, self.total_shrink)
		self.header_metadata.lcs[LC_DYSYMTAB].locreloff = self.adjust_offset(self.header_metadata.lcs[LC_DYSYMTAB].locreloff, symoff, self.shrink_by, self.total_shrink)

		if LC_ENCRYPTION_INFO in self.header_metadata.lcs:
			self.header_metadata.lcs[LC_ENCRYPTION_INFO].cryptoff = self.adjust_offset(self.header_metadata.lcs[LC_ENCRYPTION_INFO].cryptoff, symoff, self.shrink_by, self.total_shrink)

		self.header_metadata.lcs[LC_FUNCTION_STARTS].dataoff = self.adjust_offset(self.header_metadata.lcs[LC_FUNCTION_STARTS].dataoff, symoff, self.shrink_by, self.total_shrink)

		self.header_metadata.lcs[LC_DATA_IN_CODE].dataoff = self.adjust_offset(self.header_metadata.lcs[LC_DATA_IN_CODE].dataoff, symoff, self.shrink_by, self.total_shrink)

		if LC_DYLIB_CODE_SIGN_DRS in self.header_metadata.lcs:
			self.header_metadata.lcs[LC_DYLIB_CODE_SIGN_DRS].dataoff = self.adjust_offset(self.header_metadata.lcs[LC_DYLIB_CODE_SIGN_DRS].dataoff, symoff, self.shrink_by, self.total_shrink)

		if LC_CODE_SIGNATURE in self.header_metadata.lcs:
			self.header_metadata.lcs[LC_CODE_SIGNATURE].dataoff = self.adjust_offset(self.header_metadata.lcs[LC_CODE_SIGNATURE].dataoff, symoff, self.shrink_by, self.total_shrink)

		self.header_metadata.lcs[LC_SYMTAB].symoff -= self.shrink_by
		self.header_metadata.lcs[LC_SYMTAB].stroff -= self.total_shrink

	def remove_func(self, fname, func, all_funcs):
		fsize = func[SIZE]
		faddr = func[ADDR]
		diff = func[DIFF]

		if self.strategy == STRATEGY_NOPS:
			return

		if diff == 0:
			prev_func = func[PREV_FUNC]
			if prev_func is not None:
				diff = all_funcs[prev_func][DIFF]

		self.fname = fname
		self.faddr = faddr
		self.fsize = self.shrink_by = fsize + diff
		self.total_fn_size += self.fsize
		self.entry_func = all_funcs["entry0"]

		self.zero_pad += self.shrink_by
		self.shrink_by = 0

		segtext = self.header_metadata.sections["__TEXT"]["__TEXT"]
		secttext = self.header_metadata.sections["__TEXT"]["__text"]

		# wipe unnecessary symbols
		diff_syms = len(self.header_metadata.nlists)
		no_syms = self.adjust_symtable(fname)
		diff_syms -= no_syms

		# add the size of the number of symbols wiped from the symtable
		if self.binary_class == CLASS_MACHO64:
			current_shrink = self.shrink_by + (self.header_metadata.lcs[LC_SYMTAB].nsyms - no_syms) * NLIST64_SIZE
		else:
			current_shrink = self.shrink_by + (self.header_metadata.lcs[LC_SYMTAB].nsyms - no_syms) * NLIST32_SIZE
		self.total_shrink += current_shrink
		self.header_metadata.lcs[LC_SYMTAB].nsyms = no_syms

		if self.entry_func[ADDR] > self.faddr:
			self.header_metadata.lcs[LC_MAIN].entryoff -= self.fsize

		self.header_metadata.lcs[LC_DYSYMTAB].nlocalsym = dec_syms(self.header_metadata.lcs[LC_DYSYMTAB].nlocalsym, diff_syms)
		self.header_metadata.lcs[LC_DYSYMTAB].iextdefsym = dec_syms(self.header_metadata.lcs[LC_DYSYMTAB].iextdefsym, diff_syms)
		self.header_metadata.lcs[LC_DYSYMTAB].iundefsym = dec_syms(self.header_metadata.lcs[LC_DYSYMTAB].iundefsym, diff_syms)
