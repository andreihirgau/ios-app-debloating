import bap
import bap.bir
import logging
from binary_metadata import *
from util import LOGGER_NAME

frameworks = ["Photos.framework"]

framework_funcs = {}
framework_funcs["Photos.framework"] = ["__AppDelegate_imageManager_", "__AppDelegate_setImageManager:_"]

funcs_framework = {}
funcs_framework["__AppDelegate_imageManager_"] = "Photos.framework"
funcs_framework["__AppDelegate_setImageManager:_"] = "Photos.framework"

def run(binary, arch = ARCH_ARM, verbose = False):
	logger = logging.getLogger(LOGGER_NAME)
	funcs = set()
	proj = bap.run(binary)

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