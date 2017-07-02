from macholib.MachOStandalone import MachOStandalone
from macholib.MachO import MachO
from macholib.util import strip_files
import machobot.dylib as dylib
from machobot.common.macho_helpers import modify_macho_file_headers
from macholib.mach_o import *
from macholib.ptypes import *
from util import *
from header_types import *
from binary_metadata import *

# relevant load commands
LCS = [ LC_DYLD_INFO_ONLY, LC_SYMTAB, LC_DYSYMTAB, LC_LOAD_DYLINKER, LC_MAIN, LC_LOAD_DYLIB, LC_FUNCTION_STARTS, LC_DATA_IN_CODE, LC_DYLIB_CODE_SIGN_DRS, LC_ENCRYPTION_INFO, LC_DATA_IN_CODE, LC_CODE_SIGNATURE ]

FUNCS_START_BA = 0
FUNCS_START_SIZE = 1

ULONG_MAX = 4294967295

class HeaderMetadata(object):
	def __init__(self, macho, binary_class, verbose = False):
		self.verbose = verbose
		self.reset()

		self.macho = macho
		self.binary_class = binary_class
		self.collect_metadata()

	def reset(self):
		# metadata about the sections, segments and load commands
		self.sections = {}
		self.lcs = {}

		self.binary_class = None

		# list of symbols from the file's symbol table
		self.nlists = None
		self.funcs_start_data = None

		# offets and sizes from the original, unmangled, file
		self.dataoffset = 0

		self.textoffset = 0
		self.textsize = 0
		self.textvmaddr = 0
		self.TEXTsize = 0

		self.stubsoff = 0
		self.stubssize = 0

		self.function_starts_offset = 0
		self.function_starts_size = 0

		self.symoff = 0
		self.symsize = 0

		self.shoff = 0
		self.shsize = 0

		self.gotoff = 0
		self.gotsize = 0

		self.nlsymoff = 0
		self.nlsymsize = 0

		self.lasymoff = 0
		self.lasymsize = 0

		self.dyntable_offset = ULONG_MAX

	def read_tables(self):
		self.nlists = self.read_symtable()
		self.read_dynsymtable()

	def read_symtable(self):
		symtab_cmd = self.lcs[LC_SYMTAB]
		fh = open(self.macho.filename, 'rb')
		fh.seek(symtab_cmd.stroff)
		strtab = fh.read(symtab_cmd.strsize)
		fh.seek(symtab_cmd.symoff)
		nlists = []

		for i in xrange(symtab_cmd.nsyms):
			if self.binary_class == CLASS_MACHO:
				cmd = swap_nlist32_mem(nlist_32.from_fileobj(fh))
			else:
				cmd = swap_nlist64_mem(nlist_64.from_fileobj(fh))
			if cmd.n_un == 0:
				nlists.append((cmd, ''))
			else:
				sym_name = strtab[cmd.n_un:strtab.find('\x00', cmd.n_un)]
				nlists.append((cmd, sym_name))

		if self.binary_class == CLASS_MACHO:
			self.symsize = NLIST32_SIZE * len(nlists)
		else:
			self.symsize = NLIST64_SIZE * len(nlists)
			
		fh.close()
		return nlists

	def read_func_starts(self):
		cmd = self.lcs[LC_FUNCTION_STARTS]
		fh = open(self.macho.filename, 'rb')
		fh.seek(cmd.dataoff)
		ret = bytearray(fh.read(cmd.datasize))
		fh.close()
		
		return (ret, cmd.datasize)

	def read_dynsymtable(self):
		cmd = self.lcs[LC_DYSYMTAB]
		nlists = self.nlists

		self.localsyms = nlists[cmd.ilocalsym:cmd.ilocalsym + cmd.nlocalsym]
		self.extdefsyms = nlists[cmd.iextdefsym:cmd.iextdefsym + cmd.nextdefsym]
		self.undefsyms = nlists[cmd.iundefsym:cmd.iundefsym + cmd.nundefsym]

		if cmd.extrefsymoff == 0:
			self.extrefsym = None
		else:
			self.extrefsym = self.readsym(fh, cmd.extrefsymoff, cmd.nextrefsyms)

	def readsym(self, fh, off, n):
		fh.seek(off)
		refs = []
		for i in xrange(n):
			ref = dylib_reference.from_fileobj(fh)
			isym, flags = divmod(ref.isym_flags, 256)
			refs.append((self.nlists[isym], flags))
		return refs

	def collect_metadata(self):
		# scan for segments info
		got_text = False
		for h in self.macho.headers:
			for (lc, cmd, data) in h.commands:
				if lc.cmd == LC_SEGMENT_64 or lc.cmd == LC_SEGMENT:
					if SEG_TEXT in cmd.segname:
						got_text = True
						self.textvmaddr = cmd.vmaddr
						self.TEXTsize = cmd.filesize
					elif SEG_DATA in cmd.segname:
						self.dataoff = cmd.fileoff
					if not got_text:
						continue
					self.sections[cmd.segname.partition(b'\0')[0]] = {}
					self.sections[cmd.segname.partition(b'\0')[0]][cmd.segname.partition(b'\0')[0]] = cmd
					for sec in data:
						if SECT_TEXT in sec.sectname:
							self.textoffset = sec.offset
							self.textsize = sec.size
						if "__stubs" in sec.sectname or "__picsymbolstub4" in sec.sectname:
							self.stubsoff = sec.offset
							self.stubssize = sec.size
						if "__stub_helper" in sec.sectname:
							self.shoff = sec.offset
							self.shsize = sec.size
						if SEG_DATA in cmd.segname and "__nl_symbol_ptr" in sec.sectname:
							self.nlsymoff = sec.offset
							self.nlsymsize = sec.size
						elif SEG_DATA in cmd.segname and "__la_symbol_ptr" in sec.sectname:
							self.lasymoff = sec.offset
							self.lasymsize = sec.size
						self.sections[cmd.segname.partition(b'\0')[0]][sec.sectname.partition(b'\0')[0]] = sec
				elif lc.cmd in LCS:
					if lc.cmd == LC_FUNCTION_STARTS:
						self.function_starts_offset = cmd.dataoff
						self.function_starts_size = cmd.datasize
					elif lc.cmd == LC_DYSYMTAB:
						if cmd.tocoff != 0 and cmd.tocoff < self.dyntable_offset:
							self.dyntable_offset = cmd.tocoff
						if cmd.modtaboff != 0 and cmd.modtaboff < self.dyntable_offset:
							self.dyntable_offset = cmd.modtaboff
						if cmd.extrefsymoff != 0 and cmd.symoff < self.dyntable_offset:
							self.dyntable_offset = cmd.extrefsymoff
						if cmd.indirectsymoff != 0 and cmd.indirectsymoff < self.dyntable_offset:
							self.dyntable_offset = cmd.indirectsymoff
						if cmd.extreloff != 0 and cmd.extreloff < self.dyntable_offset:
							self.dyntable_offset = cmd.extreloff
						if cmd.locreloff != 0 and cmd.locreloff < self.dyntable_offset:
							self.dyntable_offset = cmd.locreloff
					elif lc.cmd == LC_SYMTAB:
						self.symoff = cmd.symoff
					self.lcs[lc.cmd] = cmd
					
		if self.verbose:
			print self.sections
			print ""
	def test(self):
		self.read_symtable()