import bap
import bap.bir
import logging
from binary_metadata import *
from util import LOGGER_NAME

def build_fw_data(data_path):
	frameworks = []
	framework_funcs = {}
	funcs_framework = {}
	last_framework = None

	with open(data_path, 'r') as fh:
		for line in fh:
			if line == '\n':
				continue

			# remove the trailing '\n'
			line = line[:-1]
			if line[len(line) - 10:] == ".framework":
				last_framework = line
				frameworks.append(line)
			elif last_framework is None:
				raise Exception("Invalid framework data file: " + data_path)
			else:
				if last_framework not in framework_funcs:
					framework_funcs[last_framework] = [line]
				else:
					framework_funcs[last_framework].append(line)
				funcs_framework[line] = last_framework

	return [frameworks, framework_funcs, funcs_framework]

def run(binary, arch = ARCH_ARM, r2 = None, data_path = "data/frameworks.dat", verbose = False):
	logger = logging.getLogger(LOGGER_NAME)
	funcs = set()
	proj = bap.run(binary)

	frameworks, framework_funcs, funcs_framework = build_fw_data(data_path)

	if arch == ARCH_X86_64:
		raise UnsupportedBinaryException("Unsupported arch: x86_64")

	subs = proj.program.subs

	detected_frameworks = []
	added_frameworks = {}

	for sub in subs:
		name = "__" + sub.name[2:]
		name = name.replace(" ", "_")
		name = name[:len(name) - 1]
		name += "_"
		if name in funcs_framework and funcs_framework[name] not in added_frameworks:
			detected_frameworks.append([funcs_framework[name], framework_funcs[funcs_framework[name]]])
			added_frameworks[funcs_framework[name]] = True

	return detected_frameworks