CLASS_MACHO 						= 0
CLASS_MACHO64						= 1

OS_OSX 								= 0
OS_IOS 								= 1

ARCH_X86_64 						= 0
ARCH_ARM 							= 1

ANALYSIS_TYPE_UNCALLED_FUNCS 		= 0
ANALYSIS_TYPE_FRAMEWORK_DATABASE 	= 1

import r2pipe
import uncalled_functions_analysis
import framework_database_analysis
from util import *

class UnsupportedBinaryException(Exception):
	def __init__(self, message):
		Exception.__init__(self, message)

class BinaryMetadata(object):
	def __init__(self, binary, analysis = ANALYSIS_TYPE_UNCALLED_FUNCS, verbose = False):
		self.binary = binary
		self.verbose = verbose
		self.binary_class = None
		self.arch = None
		self.os = None
		self.analysis_type = analysis
		self.analysis = uncalled_functions_analysis if analysis == ANALYSIS_TYPE_UNCALLED_FUNCS else framework_database_analysis

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

	def get_unused_funcs_info(self, unused_funcs):
		all_funcs = {}
		ordered_funcs = []
		info = None
		prev_func = None

		self.r2.cmd('aaa')
		results = self.r2.cmd("afl")
		funcs = []
		
		for line in results.split("\n"):
			if info is not None:
				end_addr = int(info[0], 0) + int(info[2], 0)
			else:
				end_addr = -1
			info = line.split()
			fname = line[(line.rfind(" ") + 1):].replace("sym.", '')

		 	diff = 0 if end_addr == -1 else int(info[0], 0) - end_addr
		 	if prev_func is not None:
		 		all_funcs[prev_func][DIFF] = diff
		 	all_funcs[fname] = [int(info[0], 0), int(info[2], 0), 0, prev_func]
		 	ordered_funcs.append(fname)
		 	prev_func = fname

		 	for f in unused_funcs:
				if f == fname:
					funcs.append(fname)

		if len(funcs) == 0:
			return None

		return [funcs, all_funcs, ordered_funcs]

	def get_framework_funcs_info(self, framework_funcs):
		return self.get_unused_funcs_info(framework_funcs)

	def get_func_info(self):
		analysis_data = self.analysis.run(self.binary, self.arch, self.r2)

		if self.analysis_type == ANALYSIS_TYPE_UNCALLED_FUNCS:
			return self.get_unused_funcs_info(analysis_data)
		else:
			print "Found {} frameworks:".format(len(analysis_data))
			for i in xrange(0, len(analysis_data)):
				print "{} {}".format(i + 1, analysis_data[i][0])
				if self.verbose:
					print analysis_data[i][1]
			
			#return self.get_framework_funcs_info(analysis_data)
			if len(analysis_data) == 1:
				ans = raw_input("Do you wish to remove {}?(y/n)\n".format(analysis_data[i][0]))
				if ans == 'y' or ans == None:
					return self.get_framework_funcs_info(analysis_data[1])
				else:
					return None
			else:
				ans = raw_input("Type the number of the framework that you wish to remove from the app ({}-{}) or a for all:\n".format(1, len(analysis_data)))
				if ans == 'a':
					funcs = []
					for data in analysis_data:
						funcs += data[1]
					return self.get_framework_funcs_info(funcs)
				n = int(ans)
				if n < 1 or n > len(analysis_data):
					return None
				else:
					return self.get_framework_funcs_info(analysis_data[n - 1][1])
	
	def cleanup(self):
		self.r2.quit()