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

SEC_OFFSET = 0
SEC_SIZE = 1

LA_PTR_SIZE_64 = 8

OUT_NAME = "removed.out"

class HeaderMangler(object):
	def __init__(self, exec_path):
		self.path = exec_path
		self.mangled_text_segment = False
		self.header_analyzed = False
		self.shrink_by = 0
		self.header_metadata = None

		self.fname = None
		self.faddr = 0
		self.fsize = 0

		self.total_fn_size = 0
		self.zero_pad = 0

		self.x86_64_mangler = X86_64_Mangler()

	def map_to_headers(self, out_path, fn):
		if not os.path.isfile(self.path):
			raise Exception("Invalid binary file path")
			return False

		macho = MachO(self.path)
		map(fn, macho.headers)
		out = open(out_path, 'wb')
		macho.write(out)
		out.close()

		return True

	def analyze_header(self):
		self.macho = MachO(self.path)
		self.header_metadata = HeaderMetadata(self.macho)
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

		while off < len(ladata):
			lptr = la_ptr.from_str(ladata[off:(off + LA_PTR_SIZE_64)])
			lptr.ptr = big_swap_u64(lptr.ptr)
			lptr.ptr -= shrink
			lptr.ptr = little_swap_u64(lptr.ptr)
			new_ladata += lptr.to_str()

			off += LA_PTR_SIZE_64
		return new_ladata

	def write_sections(self, in_fh, out_fh):
		# skip the header and the functions
		in_fh.seek(self.header_metadata.textoffset + self.total_fn_size)

		# write the remaining text region after adjusting its code
		text = in_fh.read(self.header_metadata.textsize - self.total_fn_size)
		text = self.x86_64_mangler.adjust_text(text, self.header_metadata.textvmaddr, self.header_metadata.textoffset, self.total_fn_size)
		out_fh.write(text)
		out_fh.write(in_fh.read(self.header_metadata.stubsoff - in_fh.tell()))

		# adjust stubs and stub helper
		stubs = in_fh.read(self.header_metadata.stubssize)
		stubs = self.x86_64_mangler.adjust_stubs(stubs, self.header_metadata.textvmaddr, self.header_metadata.stubsoff, self.total_fn_size)
		out_fh.write(stubs)

		out_fh.write(in_fh.read(self.header_metadata.shoff - in_fh.tell()))

		stub_helper = in_fh.read(self.header_metadata.shsize)
		stub_helper = self.x86_64_mangler.adjust_stub_helper(stub_helper, self.header_metadata.textvmaddr, self.header_metadata.stubsoff, self.total_fn_size)
		out_fh.write(stub_helper)

		out_fh.write(in_fh.read(self.header_metadata.dataoff - in_fh.tell()))

		# zero padding to assure the __text region fits in one or more pages exactly
		out_fh.write(bytearray(self.zero_pad))

		out_fh.write(in_fh.read(self.header_metadata.nlsymoff - in_fh.tell()))
		nldata = in_fh.read(self.header_metadata.nlsymsize)
		out_fh.write(self.adjust_nl_pointers(nldata, self.total_fn_size))

		out_fh.write(in_fh.read(self.header_metadata.lasymoff - in_fh.tell()))
		ladata = in_fh.read(self.header_metadata.lasymsize)
		out_fh.write(self.adjust_la_pointers(ladata, self.total_fn_size))

		# write the other regions until we hit the function starts
		out_fh.write(in_fh.read(self.header_metadata.function_starts_offset - in_fh.tell()))
		out_fh.write(self.header_metadata.funcs_start_data)

		# write the new function starts region
		in_fh.seek(self.header_metadata.function_starts_offset + 8)
		out_fh.write(in_fh.read(self.header_metadata.symoff - self.header_metadata.function_starts_offset - 8))

		# write the new symtable
		for sym in self.header_metadata.nlists:
		 	swap_nlist64_file(sym[0]).to_fileobj(out_fh)

		# read and write the rest of the file (dysymtable, string table etc.)
		in_fh.seek(self.header_metadata.symoff + self.header_metadata.symsize)
		out_fh.write(in_fh.read())

	def adjust_symtable(self, fname):
		copy = list(self.header_metadata.nlists)
		for i in xrange(len(copy) - 1, -1, -1):
			if fname in self.header_metadata.nlists[i][1]:
				if self.header_metadata.nlists[i][0].n_type == 36:
					del self.header_metadata.nlists[i - 1]
					del self.header_metadata.nlists[i - 1]
					del self.header_metadata.nlists[i - 1]
					del self.header_metadata.nlists[i - 1]
					i -= 4
				else:
					del self.header_metadata.nlists[i]
			elif self.header_metadata.nlists[i][0].n_type == 36 and "_" in self.header_metadata.nlists[i][1]:
				self.header_metadata.nlists[i][0].n_value -= self.total_fn_size
				self.header_metadata.nlists[i - 1][0].n_value -= self.total_fn_size
			# fix this hardcode
			elif "_main" in self.header_metadata.nlists[i][1]:
				self.header_metadata.nlists[i][0].n_value -= self.total_fn_size
				self.header_metadata.nlists[i - 1][0].n_value -= self.total_fn_size

		return len(self.header_metadata.nlists)

	def adjust_function_starts(self, fname):
		funcs = self.header_metadata.read_func_starts()
		x = decode_uleb128(funcs[FUNCS_START_BA], 0)
		funcs_ba = bytearray()
		addr = x[ULEB_DATA]
		old_offset = 0
		found = False

		while x[ULEB_OFF] != funcs[FUNCS_START_SIZE]:
			if addr == self.faddr:
				found = True
			old_offset = x[ULEB_OFF]
			x = decode_uleb128(funcs[FUNCS_START_BA], x[ULEB_OFF])
			addr += x[ULEB_DATA]

			if found:
				break

		funcs_ba = funcs[FUNCS_START_BA][:old_offset] + bytearray(x[ULEB_OFF] - old_offset) + funcs[FUNCS_START_BA][x[ULEB_OFF]:]
		self.header_metadata.funcs_start_data = funcs_ba

	def adjust_offset(self, off, symoff, shrink, total_shrink):
		if off <= 0:
			return off
		elif off > symoff:
			return off - total_shrink
		else:
			return off - shrink

	# TODO: needs more robustness work, in particular supporing any number of functions
	# placed anywhere inside the binary file
	def remove_func(self, in_file, fname, faddr, fsize):
		self.fname = fname
		self.faddr = faddr
		# TODO fix this hardcode asap
		self.fsize = self.shrink_by = fsize + 14
		self.total_fn_size = self.fsize

		if self.total_fn_size < PAGE_SIZE:
			self.zero_pad = self.shrink_by
			self.shrink_by = 0
		else:
			# TODO funcs > 4096
			pass

		if not self.header_analyzed:
			self.analyze_header()

		segtext = self.header_metadata.sections["__TEXT"]["__TEXT"]
		secttext = self.header_metadata.sections["__TEXT"]["__text"]

		diff_syms = len(self.header_metadata.nlists)
		no_syms = self.adjust_symtable(fname)
		diff_syms -= no_syms

		# add the size of the number of symbols wiped from the symtable
		total_shrink = self.shrink_by + (self.header_metadata.lcs[LC_SYMTAB].nsyms - no_syms) * NLIST64_SIZE
		self.header_metadata.lcs[LC_SYMTAB].nsyms = no_syms
		symoff = self.header_metadata.lcs[LC_SYMTAB].symoff
		self.header_metadata.lcs[LC_SYMTAB].symoff -= self.shrink_by
		self.header_metadata.lcs[LC_SYMTAB].stroff = self.header_metadata.lcs[LC_SYMTAB].stroff - total_shrink

		self.adjust_function_starts(fname)
		segtextaddr = segtext.vmaddr
		segtextoff = segtext.fileoff 
		secttextaddr = secttext.addr

		for segname, _ in self.header_metadata.sections.iteritems():
			for sectname, cmd in self.header_metadata.sections[segname].iteritems():
				if isinstance(cmd, segment_command_64):
					if SEG_DATA in cmd.segname:
						cmd.fileoff -= self.shrink_by
					if cmd.fileoff > secttext.offset:
						pass
					if SEG_LINKEDIT in cmd.segname:
						cmd.filesize = cmd.filesize - total_shrink - self.shrink_by
				elif SEG_TEXT in segname and SECT_TEXT not in cmd.sectname:
					cmd.addr -= self.total_fn_size
					cmd.offset -= self.total_fn_size
				else:
					if cmd.offset > secttext.offset and SEG_TEXT in segname:
						cmd.offset -= self.total_fn_size

		segtext.filesize -= self.shrink_by
		secttext.size -= self.total_fn_size

		self.header_metadata.lcs[LC_DYLD_INFO_ONLY].rebase_off = self.adjust_offset(self.header_metadata.lcs[LC_DYLD_INFO_ONLY].rebase_off, symoff, self.shrink_by, total_shrink)
		self.header_metadata.lcs[LC_DYLD_INFO_ONLY].bind_off = self.adjust_offset(self.header_metadata.lcs[LC_DYLD_INFO_ONLY].bind_off, symoff, self.shrink_by, total_shrink)
		self.header_metadata.lcs[LC_DYLD_INFO_ONLY].weak_bind_off = self.adjust_offset(self.header_metadata.lcs[LC_DYLD_INFO_ONLY].weak_bind_off, symoff, self.shrink_by, total_shrink)
		self.header_metadata.lcs[LC_DYLD_INFO_ONLY].lazy_bind_off = self.adjust_offset(self.header_metadata.lcs[LC_DYLD_INFO_ONLY].lazy_bind_off, symoff, self.shrink_by, total_shrink)
		self.header_metadata.lcs[LC_DYLD_INFO_ONLY].export_off = self.adjust_offset(self.header_metadata.lcs[LC_DYLD_INFO_ONLY].export_off, symoff, self.shrink_by, total_shrink)

		self.header_metadata.lcs[LC_DYSYMTAB].tocoff = self.adjust_offset(self.header_metadata.lcs[LC_DYSYMTAB].tocoff, symoff, self.shrink_by, total_shrink)
		self.header_metadata.lcs[LC_DYSYMTAB].indirectsymoff = self.adjust_offset(self.header_metadata.lcs[LC_DYSYMTAB].indirectsymoff, symoff, self.shrink_by, total_shrink)
		self.header_metadata.lcs[LC_DYSYMTAB].modtaboff = self.adjust_offset(self.header_metadata.lcs[LC_DYSYMTAB].modtaboff, symoff, self.shrink_by, total_shrink)
		self.header_metadata.lcs[LC_DYSYMTAB].extrefsymoff = self.adjust_offset(self.header_metadata.lcs[LC_DYSYMTAB].extrefsymoff, symoff, self.shrink_by, total_shrink)
		self.header_metadata.lcs[LC_DYSYMTAB].extreloff = self.adjust_offset(self.header_metadata.lcs[LC_DYSYMTAB].extreloff, symoff, self.shrink_by, total_shrink)
		self.header_metadata.lcs[LC_DYSYMTAB].locreloff = self.adjust_offset(self.header_metadata.lcs[LC_DYSYMTAB].locreloff, symoff, self.shrink_by, total_shrink)

		# # TODO: see if the main function was actually declared after the removed function
		self.header_metadata.lcs[LC_MAIN].entryoff -= self.total_fn_size

		self.header_metadata.lcs[LC_FUNCTION_STARTS].dataoff = self.adjust_offset(self.header_metadata.lcs[LC_FUNCTION_STARTS].dataoff, symoff, self.shrink_by, total_shrink)

		self.header_metadata.lcs[LC_DATA_IN_CODE].dataoff = self.adjust_offset(self.header_metadata.lcs[LC_DATA_IN_CODE].dataoff, symoff, self.shrink_by, total_shrink)

		self.header_metadata.lcs[LC_DYLIB_CODE_SIGN_DRS].dataoff = self.adjust_offset(self.header_metadata.lcs[LC_DYLIB_CODE_SIGN_DRS].dataoff, symoff, self.shrink_by, total_shrink)
		self.header_metadata.lcs[LC_DYSYMTAB].nlocalsym -= diff_syms
		self.header_metadata.lcs[LC_DYSYMTAB].iextdefsym -= diff_syms
		self.header_metadata.lcs[LC_DYSYMTAB].iundefsym -= diff_syms

		fh = open(OUT_NAME, 'wb')
		in_fh = open(in_file, 'rb')
		self.write_header(fh, total_shrink)
		self.write_sections(in_fh, fh)
		in_fh.close()
		fh.close()

