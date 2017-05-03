from capstone import *
from capstone.x86 import *
from keystone import *

class X86_64_Mangler(object):
	def __init__(self, verbose = False):
		self.cs_mi = Cs(CS_ARCH_X86, CS_MODE_64)
		self.ks_mi = Ks(KS_ARCH_X86, KS_MODE_64)
		self.cs_mi.detail = True
		self.verbose = verbose

	def adjust_stub_helper(self, stub_helper, vmaddr, helperoff, removed):
		got_nop = False
		new_stub_helper = bytearray()
		c = 0

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
						mem_disp = i.value.mem.disp + removed
						imm_repl = asm_str[asm_str.find("0x"):]
						asm_str = asm_str.replace(imm_repl, str(mem_disp) + "]")
						encoding, count = self.ks_mi.asm(bytes(asm_str))
						break
				else:
					asm_str = insn.mnemonic + " " + insn.op_str
					encoding, count = self.ks_mi.asm(bytes(asm_str))

			new_stub_helper += bytearray(encoding)

			c += insn.size
		return new_stub_helper

	def adjust_stubs(self, stubs, vmaddr, textoff, removed):
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
					mem_disp = i.value.mem.disp + removed
					imm_repl = asm_str[asm_str.find("0x"):]
					asm_str = asm_str.replace(imm_repl, str(mem_disp) + "]")

					if self.verbose:
						print asm_str
					encoding, count = self.ks_mi.asm(bytes(asm_str))
				else:
					encoding, count = self.ks_mi.asm(bytes(insn.mnemonic + " " + insn.op_str))
			new_stubs += bytearray(encoding)
		return new_stubs

	def adjust_text(self, text, vmaddr, textoff, removed):
		new_text = bytearray()
		for insn in self.cs_mi.disasm(text, vmaddr + textoff):

			if self.verbose:
				print("0x%x:\t%s\t%s" % (insn.address, insn.mnemonic, insn.op_str))

			if len(insn.operands) == 0:
				encoding, count = self.ks_mi.asm(bytes(insn.mnemonic + " " + insn.op_str))
				new_text += bytearray(encoding)
				continue

			for i in insn.operands:
				if i.type == X86_OP_REG:
					encoding, count = self.ks_mi.asm(bytes(insn.mnemonic + " " + insn.op_str))
				if i.type == X86_OP_IMM:
					if insn.id == X86_INS_CALL and i.value.imm > vmaddr + textoff:
						encoding, count = self.ks_mi.asm(bytes(insn.mnemonic + " " + hex(i.value.imm - insn.address)))
					else:
						encoding, count = self.ks_mi.asm(bytes(insn.mnemonic + " " + insn.op_str))

				if i.type == X86_OP_MEM:
					if i.value.mem.base == X86_REG_RIP:
						if i.value.mem.disp != 0 and insn.address + i.value.mem.disp < vmaddr + textoff:
							asm_str = insn.mnemonic + " " + insn.op_str
							mem_disp = i.value.mem.disp + removed
							imm_repl = asm_str[asm_str.find("0x"):]
							asm_str = asm_str.replace(imm_repl, str(mem_disp) + "]")

							if self.verbose:
								print asm_str
							encoding, count = self.ks_mi.asm(bytes(asm_str))
						else:
							encoding, count = self.ks_mi.asm(bytes(insn.mnemonic + " " + insn.op_str))
					else:
						encoding, count = self.ks_mi.asm(bytes(insn.mnemonic + " " + insn.op_str))

			new_text += bytearray(encoding)

		return new_text