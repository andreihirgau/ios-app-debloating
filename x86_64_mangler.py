from capstone import *
from capstone.x86 import *
from keystone import *
from util import *

class X86_64_Mangler(object):
	def __init__(self, verbose = False):
		self.cs_mi = Cs(CS_ARCH_X86, CS_MODE_64)
		self.ks_mi = Ks(KS_ARCH_X86, KS_MODE_64)
		self.cs_mi.detail = True
		self.verbose = verbose

	def adjust_fn(self, func_meta, func_body, vmaddr, rem_funcs, all_funcs):
		new_fn = bytearray()
		for insn in self.cs_mi.disasm(func_body, vmaddr + func_meta[ADDR]):
			if self.verbose:
				print("0x%x:\t%s\t%s" % (insn.address, insn.mnemonic, insn.op_str))

			if len(insn.operands) == 0:
				encoding, count = self.ks_mi.asm(bytes(insn.mnemonic + " " + insn.op_str))
				new_fn += bytearray(encoding)
				continue

			for i in insn.operands:
				if i.type == X86_OP_REG:
					encoding, count = self.ks_mi.asm(bytes(insn.mnemonic + " " + insn.op_str))
				if i.type == X86_OP_IMM:
					total_disp = i.value.imm
					if insn.id == X86_INS_CALL:
						for func in rem_funcs:
							if insn.address < vmaddr + all_funcs[func][ADDR]:
								diff = all_funcs[func][DIFF]
								if diff == 0:
									diff = all_funcs[all_funcs[func][PREV_FUNC]][DIFF]
								total_disp = total_disp - all_funcs[func][SIZE] - diff
								
						asm_str = insn.mnemonic + " " + hex(total_disp - insn.address)
						print asm_str
						encoding, count = self.ks_mi.asm(bytes(asm_str))
					else:
						encoding, count = self.ks_mi.asm(bytes(insn.mnemonic + " " + insn.op_str))

				if i.type == X86_OP_MEM:
					if i.value.mem.base == X86_REG_RIP:
						mem_disp = i.value.mem.disp
						for func in rem_funcs:
							if i.value.mem.disp != 0 and insn.address < vmaddr + all_funcs[func][ADDR]:
								diff = all_funcs[func][DIFF]
								if diff == 0:
									diff = all_funcs[all_funcs[func][PREV_FUNC]][DIFF]
								mem_disp = mem_disp - all_funcs[func][SIZE] - diff
						asm_str = insn.mnemonic + " " + insn.op_str
						imm_repl = asm_str[asm_str.find("0x"):]
						asm_str = asm_str.replace(imm_repl, str(mem_disp) + "]")

						if self.verbose:
							print asm_str

						encoding, count = self.ks_mi.asm(bytes(asm_str))
					else:
						encoding, count = self.ks_mi.asm(bytes(insn.mnemonic + " " + insn.op_str))

			new_fn += bytearray(encoding)

		return new_fn

	def adjust_stubs(self, stubs, textoff, vmaddr, total_removed):
		new_stubs = bytearray()
		for insn in self.cs_mi.disasm(stubs, vmaddr + textoff):
			if self.verbose:
				print("0x%x:\t%s\t%s" % (insn.address, insn.mnemonic, insn.op_str))

			if insn.id != X86_INS_JMP:
				encoding, count = self.ks_mi.asm(bytes(insn.mnemonic + " " + insn.op_str))
				new_stubs += bytearray(encoding)
				continue
			for i in insn.operands:
				if i.type != X86_OP_MEM:
					encoding, count = self.ks_mi.asm(bytes(insn.mnemonic + " " + insn.op_str))
					break

				if i.type == X86_OP_MEM:
					asm_str = insn.mnemonic + " " + insn.op_str
					mem_disp = i.value.mem.disp + total_removed
					imm_repl = asm_str[asm_str.find("0x"):]
					asm_str = asm_str.replace(imm_repl, str(hex(mem_disp)) + "]")

					if self.verbose:
						print asm_str
					encoding, count = self.ks_mi.asm(bytes(asm_str))
				else:
					encoding, count = self.ks_mi.asm(bytes(insn.mnemonic + " " + insn.op_str))
			new_stubs += bytearray(encoding)
		return new_stubs

	def adjust_stub_helper(self, stub_helper, vmaddr, helperoff, total_removed):
		got_nop = False
		new_stub_helper = bytearray()
		c = 0
		self.verbose = True

		for insn in self.cs_mi.disasm(stub_helper, vmaddr + helperoff):
			if self.verbose:
				print("0x%x:\t%s\t%s" % (insn.address, insn.mnemonic, insn.op_str))

			if insn.id == X86_INS_NOP:
				got_nop = True
			if got_nop:
				new_stub_helper += stub_helper[c:]
				break

			for i in insn.operands:
				if i.type == X86_OP_MEM:
					if i.value.mem.base != 0 and i.value.mem.base == X86_REG_RIP:
						asm_str = insn.mnemonic + " " + insn.op_str
						mem_disp = i.value.mem.disp + total_removed
						imm_repl = asm_str[asm_str.find("0x"):]
						asm_str = asm_str.replace(imm_repl, str(mem_disp) + "]")

						if self.verbose:
							print asm_str

						encoding, count = self.ks_mi.asm(bytes(asm_str))
						break
				else:
					asm_str = insn.mnemonic + " " + insn.op_str
					encoding, count = self.ks_mi.asm(bytes(asm_str))

			new_stub_helper += bytearray(encoding)

			c += insn.size
		return new_stub_helper