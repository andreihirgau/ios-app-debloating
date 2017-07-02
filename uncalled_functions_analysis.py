import bap
import bap.bir
import logging
from binary_metadata import *
from util import LOGGER_NAME

def run(binary, arch, r2 = None, verbose = False):
	logger = logging.getLogger(LOGGER_NAME)
	funcs = set()
	proj = bap.run(binary)

	if arch == ARCH_X86_64:
		stubs = proj.sections['__stubs']
	elif arch == ARCH_ARM:
		stubs = proj.sections["__picsymbolstub4"]
	else:
		raise Exception("Unknown arch: " + arch)

	subs = proj.program.subs

	for sub in subs:
		if sub.name != "_main" and "stub helpers" not in sub.name and "stub_helpers" not in sub.name:
			funcs.add(sub.name)

	if verbose:
		logger.info("Analyser found the current functions in the binary file: ")
		logger.info(funcs)

	for sub in subs:
		# ignore stubs
		if verbose:
			logger.info("[ANALYSER] Sub (%d, %s)", sub.id, sub.name)

		for blk in sub.blks:
			if "address" not in blk.attrs:
				continue
			else:
				faddr = int(blk.attrs["address"][:blk.attrs["address"].find(":")], 0)
				break

		if faddr >= stubs.beg:
			continue

		for blk in sub.blks:
			for jmp in blk.jmps:
				# ignore returns
				if isinstance(jmp, bap.bir.Call) or isinstance(jmp, bap.bir.Goto):
					if isinstance(jmp.target, tuple):
						if isinstance(jmp.target[0], bap.bir.Direct):
							for target in jmp.target:
								funcs.discard(target.arg.name[1:])
					else:
						if isinstance(jmp.target, bap.bir.Direct):
							funcs.discard(jmp.target.arg.name[1:])

	if r2 is not None:
		r2.cmd("af")
		results = r2.cmd("afl")

		for line in results.split("\n"):
			fname = line[(line.rfind(" ") + 1):].replace("sym.", '')
			if fname in funcs:
				funcs.remove(fname)

	return funcs