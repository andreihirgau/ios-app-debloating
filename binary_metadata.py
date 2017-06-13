import r2pipe
import analysis
from util import *

CLASS_MACHO 	= 0
CLASS_MACHO64	= 1

OS_OSX 			= 0
OS_IOS 			= 1

ARCH_X86_64 	= 0
ARCH_ARM 		= 1

class UnsupportedBinaryException(Exception):
	def __init__(self, message):
		Exception.__init__(self, message)

class BinaryMetadata(object):
	def __init__(self, binary, verbose = False):
		self.binary = binary
		self.verbose = verbose
		self.binary_class = None
		self.arch = None
		self.os = None

		self.r2 = r2pipe.open(binary, ['-B', ' 0x0'])
		info = self.r2.cmd('i')

		for line in info.split("\n"):
			if line.startswith("class"):
				binary_class = line[5:].strip()
				if binary_class == "MACH0":
					self.binary_class = CLASS_MACHO
				elif binary_class == "MACH064":
					self.binary_class = CLASS_MACHO64
				else:
					raise UnsupportedBinaryException("Unsupported binary file class: " + binary_class)
			elif line.startswith("arch"):
				arch = line[4:].strip()
				if arch == "arm":
					self.arch = ARCH_ARM
				elif arch == "x86" and self.binary_class == CLASS_MACHO64:
					self.arch = ARCH_X86_64
				else:
					raise UnsupportedBinaryException("Unsupported arch: " + arch)
			elif line.startswith("os"):
				os = line[2:].strip()
				if os == "ios":
					self.os = OS_IOS
				elif os == "osx":
					self.os = OS_OSX
				else:
					raise UnsupportedBinaryException("Unsupported os: " + os)

	def get_func_info(self):
		all_funcs = {}
		ordered_funcs = []
		info = None
		prev_func = None

		unused_funcs = analysis.run(self.binary, self.arch)
		self.r2.cmd('aaa')
		results = self.r2.cmd("afl")
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

		 	for f in unused_funcs:
				if f == fname:
					funcs.append(info[3].replace('sym.', ''))

		if len(funcs) == 0:
			return None

		return [funcs, all_funcs, ordered_funcs]
	
	def cleanup(self):	
		self.r2.quit()