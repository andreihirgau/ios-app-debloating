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

SEC_OFFSET = 0
SEC_SIZE = 1

OUT_NAME = "removed.out"

def dec_syms(syms, amount):
	if syms - amount < 0:
		return syms
	else:
		return syms - amount

class HeaderMangler(object):
	def __init__(self, binary_class, arch, exec_path):
		self.path = exec_path
		self.mangled_text_segment = False
		self.header_analyzed = False
		self.shrink_by = 0
		self.header_metadata = None

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

		self.__TEXT_orig = None

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
		self.__TEXT_orig = in_fh.read(self.header_metadata.TEXTsize - self.header_metadata.textoffset)

	# This should be called after the header has been written
	def new_write_sections(self, in_fh, out_fh, funcs, all_funcs, ordered_funcs):
		# Write the remaining data between text and the header
		in_fh.seek(self.header_metadata.textoffset)
		diff = 0

		out_fh.write(in_fh.read(out_fh.tell() - self.header_metadata.textoffset))
		first_func = all_funcs[ordered_funcs[0]]
		out_fh.write(in_fh.read(out_fh.tell() - first_func[ADDR]))

		# Adjust functions
		for i in xrange(0, len(ordered_funcs)):
			if ordered_funcs[i] in funcs:
				continue
			offset = all_funcs[ordered_funcs[i]][ADDR] - self.header_metadata.textoffset
			size = all_funcs[ordered_funcs[i]][SIZE]
			if offset + size > self.header_metadata.textsize:
				break
			out_fh.write(self.code_mangler.adjust_fn(all_funcs[ordered_funcs[i]], self.__TEXT_orig[offset:(offset + size)], self.header_metadata.textvmaddr, self.text_pad, funcs, all_funcs))

		print "padding __text with: " + str(self.text_pad)
		out_fh.write(self.code_mangler.get_pad(self.text_pad))

		stubsoff = self.header_metadata.stubsoff - self.header_metadata.textoffset
		diff += (stubsoff - self.header_metadata.textsize)
		out_fh.write(self.__TEXT_orig[self.header_metadata.textsize:stubsoff])

		# Adjust stubs
		stubs = self.__TEXT_orig[stubsoff:(stubsoff + self.header_metadata.stubssize)]
		out_fh.write(self.code_mangler.adjust_stubs(stubs, self.header_metadata.textvmaddr, self.header_metadata.stubsoff, self.total_fn_size))

		shoff = self.header_metadata.shoff - self.header_metadata.textoffset
		start = self.header_metadata.textsize + self.header_metadata.stubssize + diff
		out_fh.write(self.__TEXT_orig[start:shoff])

		# Adjust stub helper
		stub_helper = self.__TEXT_orig[shoff:(shoff + self.header_metadata.shsize)]
		out_fh.write(self.code_mangler.adjust_stub_helper(stub_helper, self.header_metadata.textvmaddr, self.header_metadata.shoff, self.total_fn_size))

		out_fh.write(self.__TEXT_orig[(shoff + self.header_metadata.shsize):])

		# zero padding to assure the __text region fits in one or more pages exactly
		out_fh.write(bytearray(self.zero_pad))

		in_fh.seek(self.header_metadata.dataoff)

		out_fh.write(in_fh.read(self.header_metadata.nlsymoff - in_fh.tell()))
		nldata = in_fh.read(self.header_metadata.nlsymsize)
		out_fh.write(self.adjust_nl_pointers(nldata, self.total_fn_size))

		out_fh.write(in_fh.read(self.header_metadata.lasymoff - in_fh.tell()))
		ladata = in_fh.read(self.header_metadata.lasymsize)
		out_fh.write(self.adjust_la_pointers(ladata, self.total_fn_size))

		# write the other regions until we hit the function starts
		out_fh.write(in_fh.read(self.header_metadata.function_starts_offset - in_fh.tell()))
		out_fh.write(self.header_metadata.funcs_start_data)
		in_fh.seek(in_fh.tell() + len(self.header_metadata.funcs_start_data))

		# write the new function starts region
		out_fh.write(in_fh.read(self.header_metadata.symoff - in_fh.tell()))

		# write the new symtable
		for sym in self.header_metadata.nlists:
			if self.binary_class == CLASS_MACHO:
		 		swap_nlist32_file(sym[0]).to_fileobj(out_fh)
		 	else:
		 		swap_nlist64_file(sym[0]).to_fileobj(out_fh)

		# read and write the rest of the file (dysymtable, string table etc.)
		in_fh.seek(self.header_metadata.symoff + self.header_metadata.symsize)
		out_fh.write(in_fh.read())

	def adjust_symtable(self, fname):
		ntype = 36 if self.binary_class == CLASS_MACHO64 else 15
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
				print "n_value: " + str(self.header_metadata.nlists[i][0].n_value)
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

		fh = open(self.path, 'rb')
		self.read_TEXT_segment(fh)

		for f in funcs:
			self.remove_func(f, all_funcs[f], all_funcs)

		# after we've made the changes to remove the functions, adjust the load commands
		self.adjust_lcs()
		self.adjust_function_starts(funcs, all_funcs)

		out_fh = open(OUT_NAME, 'wb')
		self.write_header(out_fh, self.total_shrink)
		self.new_write_sections(fh, out_fh, funcs, all_funcs, ordered_funcs)
		out_fh.close()

	def adjust_lcs(self):
		# stubs are in ARM mode (4 bytes / insn) and __text is in thumb mode (2 bytes / insn) 
		# force the alignment of the stubs region to 4 bytes
		if self.arch == ARCH_ARM and self.fsize % 4 != 0:
			self.text_pad = 2
			self.fsize -= self.text_pad
			self.total_fn_size -= self.text_pad
			self.zero_pad -= self.text_pad

		# we can't possibly remove an odd number of bytes from ARM code, so something has gone wrong
		if self.arch == ARCH_ARM:
			assert(self.fsize % 4 == 0)

		segtext = self.header_metadata.sections["__TEXT"]["__TEXT"]
		secttext = self.header_metadata.sections["__TEXT"]["__text"]

		symoff = self.header_metadata.lcs[LC_SYMTAB].symoff

		for segname, _ in self.header_metadata.sections.iteritems():
			for sectname, cmd in self.header_metadata.sections[segname].iteritems():
				if isinstance(cmd, segment_command_64) or isinstance(cmd, segment_command):
					if SEG_DATA in cmd.segname:
						cmd.fileoff -= self.shrink_by
					if cmd.fileoff > secttext.offset:
						pass
					if SEG_LINKEDIT in cmd.segname:
						cmd.filesize = cmd.filesize - self.total_shrink - self.shrink_by
				elif SEG_TEXT in segname and SECT_TEXT not in cmd.sectname:
					cmd.addr -= self.fsize
					cmd.offset -= self.fsize
				else:
					if SECT_TEXT in cmd.sectname:
						cmd.size += self.text_pad
						print "text"
					if cmd.offset > secttext.offset and SEG_TEXT in segname:
						print "here"
						cmd.offset -= self.fsize

		segtext.filesize -= self.shrink_by
		secttext.size -= self.fsize

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

		if LC_ENCRYPTION_INFO_64 in self.header_metadata.lcs:
			self.header_metadata.lcs[LC_ENCRYPTION_INFO_64].cryptoff = self.adjust_offset(self.header_metadata.lcs[LC_ENCRYPTION_INFO_64].cryptoff, symoff, self.shrink_by, self.total_shrink)

		self.header_metadata.lcs[LC_FUNCTION_STARTS].dataoff = self.adjust_offset(self.header_metadata.lcs[LC_FUNCTION_STARTS].dataoff, symoff, self.shrink_by, self.total_shrink)

		self.header_metadata.lcs[LC_DATA_IN_CODE].dataoff = self.adjust_offset(self.header_metadata.lcs[LC_DATA_IN_CODE].dataoff, symoff, self.shrink_by, self.total_shrink)

		if LC_DYLIB_CODE_SIGN_DRS in self.header_metadata.lcs:
			self.header_metadata.lcs[LC_DYLIB_CODE_SIGN_DRS].dataoff = self.adjust_offset(self.header_metadata.lcs[LC_DYLIB_CODE_SIGN_DRS].dataoff, symoff, self.shrink_by, self.total_shrink)

		self.header_metadata.lcs[LC_SYMTAB].symoff -= self.shrink_by
		self.header_metadata.lcs[LC_SYMTAB].stroff -= self.total_shrink

	def remove_func(self, fname, func, all_funcs):
		fsize = func[SIZE]
		faddr = func[ADDR]
		diff = func[DIFF]

		if diff == 0:
			prev_func = func[PREV_FUNC]
			if prev_func is not None:
				diff = all_funcs[prev_func][DIFF]

		self.fname = fname
		self.faddr = faddr
		self.fsize = self.shrink_by = fsize + diff
		self.total_fn_size += self.fsize
		self.entry_func = all_funcs["entry0"]

		if self.total_fn_size < PAGE_SIZE:
			self.zero_pad += self.shrink_by
			self.shrink_by = 0
		else:
			# TODO funcs > 4096
			pass

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
