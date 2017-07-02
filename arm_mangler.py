from capstone import *
from capstone.arm import *
from keystone import *
from util import *

def hexbytes(insn):
	b = buffer(insn.bytes)
	if len(insn.bytes) == 4:
		return "0x%08x" % (struct.unpack_from('I', b))
	elif len(insn.bytes) == 2:
		return "0x%04x" % (struct.unpack_from('H', b))

def is_insn_branch(insn_id):
	return insn_id == ARM_INS_B or insn_id == ARM_INS_BL or \
		insn_id == ARM_INS_BLX or insn_id == ARM_INS_BFC or \
		insn_id == ARM_INS_BFI or insn_id == ARM_INS_BIC or \
		insn_id == ARM_INS_BKPT


class ARM_Mangler(object):
	def __init__(self, verbose = False):
		self.cs_thumb_mi = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
		self.ks_thumb_mi = Ks(KS_ARCH_ARM, KS_MODE_THUMB)
		self.cs_arm_mi = Cs(CS_ARCH_ARM, CS_MODE_ARM)
		self.ks_arm_mi = Ks(KS_ARCH_ARM, KS_MODE_ARM)

		self.cs_thumb_mi.detail = True
		self.cs_arm_mi.detail = True

		self.movw = None
		self.movt = None

		self.movw_imm = None
		self.movt_imm = None

		self.verbose = verbose

	def get_nops(self, byte_count, mode = KS_MODE_THUMB):
		text = bytearray()

		while byte_count > 0:
			if mode == KS_MODE_THUMB:
				encoding, count = self.ks_thumb_mi.asm(bytes("nop"))
				byte_count -= 2
			else:
				encoding, count = self.ks_arm_mi.asm(bytes("nop"))
				byte_count -= 4
			text += bytearray(encoding)

		return text		

	def get_pad(self, byte_count):
		if byte_count % 4 == 0:
			return ''

		text = bytearray()

		# we can't pad ARM code with an odd number of bytes
		assert(byte_count % 2 == 0)

		# pad the __text section with nops (thumb mode -> 2 bytes per nop)
		while byte_count > 0:
			encoding, count = self.ks_thumb_mi.asm(bytes("nop"))
			text += bytearray(encoding)
			byte_count -= 2

		return text

	def adjust_fn(self, func_meta, func_body, vmaddr, pad, dataoff, stubsoff, rem_funcs, all_funcs):
		new_fn = bytearray()
		self.verbose = False

		stubsoff += pad

		for insn in self.cs_thumb_mi.disasm(func_body, vmaddr + func_meta[ADDR]):
			if self.verbose:
				print("0x%x:\t%s\t%s" % (insn.address, insn.mnemonic, insn.op_str))

			if len(insn.operands) == 0:
				encoding, count = self.ks_thumb_mi.asm(bytes(insn.mnemonic + " " + insn.op_str))
				new_fn += bytearray(encoding)
				continue

			if insn.id == ARM_INS_MOVT:
				imm = False
				for i in insn.operands:
					if i.type == ARM_OP_IMM:
						self.movt_imm = i
						imm = True
						break
 
				if imm:
					self.movt = insn
				else:
					self.movw = None
					self.movt = None

					encoding, count = self.ks_thumb_mi.asm(bytes(insn.mnemonic + " " + insn.op_str))
					new_fn += bytearray(encoding)
			elif insn.id == ARM_INS_MOVW:
				imm = False
				for i in insn.operands:
					if i.type == ARM_OP_IMM:
						self.movw_imm = i
						imm = True
						break

				if imm:
					self.movw = insn
				else:
					self.movw = None
					self.movt = None

					encoding, count = self.ks_thumb_mi.asm(bytes(insn.mnemonic + " " + insn.op_str))
					new_fn += bytearray(encoding)
			elif insn.id == ARM_INS_ADD and self.movt is not None and self.movw is not None:
				# make sure the stored movt and movw instructions work with the same register
				r1 = None
				imm1 = None
				imm2 = None

				for i in self.movt.operands:
					if i.type == ARM_OP_REG:
						r1 = i
						break

				for i in self.movw.operands:
					if i.type == ARM_OP_REG:
						if i.reg != r1.reg:
							r1 = None
							break

				has_pc = False
				for i in insn.operands:
					if i.reg == ARM_REG_PC:
						has_pc = True
						break

				if has_pc and r1 is not None:
					# movw reg, imm_val
					# movt reg, imm_val
					# add reg, pc

					# compute the address added to pc
					total_disp = (self.movt_imm.value.imm << 16) | self.movw_imm.value.imm
					for func in rem_funcs:
						if insn.address > vmaddr + all_funcs[func][ADDR]:
							continue
						elif insn.address + total_disp >= vmaddr + dataoff:
							diff = all_funcs[func][DIFF]
							if diff == 0:
								diff = all_funcs[all_funcs[func][PREV_FUNC]][DIFF]
							total_disp = total_disp - all_funcs[func][SIZE] - diff
						elif insn.address < vmaddr + all_funcs[func][ADDR]:
							diff = all_funcs[func][DIFF]
							if diff == 0:
								diff = all_funcs[all_funcs[func][PREV_FUNC]][DIFF]
							total_disp = total_disp - all_funcs[func][SIZE] - diff

					total_disp += pad
					reg = self.movw.op_str[:self.movw.op_str.find(",")]

					# now generate and write the new movt and movw instructions with the low and high bits of the new address
					encoding, count = self.ks_thumb_mi.asm(bytes(self.movw.mnemonic + " " + reg + ", " + str((total_disp & 0xffff))))
					new_fn += bytearray(encoding)

					encoding, count = self.ks_thumb_mi.asm(bytes(self.movt.mnemonic + " " + reg + ", " + str((total_disp >> 16))))
					new_fn += bytearray(encoding)
				else:
					encoding, count = self.ks_thumb_mi.asm(bytes(self.movw.mnemonic + " " + self.movw.op_str))
					new_fn += bytearray(encoding)
					encoding, count = self.ks_thumb_mi.asm(bytes(self.movt.mnemonic + " " + self.movt.op_str))
					new_fn += bytearray(encoding)

				# the add reg, pc instruction remains the same
				encoding, count = self.ks_thumb_mi.asm(bytes(insn.mnemonic + " " + insn.op_str))
				new_fn += bytearray(encoding)

				self.movt = None
				self.movw = None
			else:
				# write the stored movt / movw instructions (if any)
				if self.movw is not None:
					encoding, count = self.ks_thumb_mi.asm(bytes(self.movw.mnemonic + " " + self.movw.op_str))
					new_fn += bytearray(encoding)
					self.movw = None
				if self.movt is not None:
					encoding, count = self.ks_thumb_mi.asm(bytes(self.movt.mnemonic + " " + self.movt.op_str))
					new_fn += bytearray(encoding)
					self.movt = None

				if len(insn.operands) == 1 and insn.operands[0].type == ARM_OP_IMM and insn.id == ARM_INS_BLX:
					for i in insn.operands:						
						total_disp = i.value.imm
						for func in rem_funcs:
							# print hex(vmaddr + all_funcs[func][ADDR])
							# if insn.address > vmaddr + all_funcs[func][ADDR]:
							# 	continue
							if insn.address > vmaddr + all_funcs[func][ADDR] + all_funcs[func][SIZE]:
								continue
							diff = all_funcs[func][DIFF]
							if diff == 0:
								diff = all_funcs[all_funcs[func][PREV_FUNC]][DIFF]

							if total_disp >= vmaddr + dataoff:
								diff = all_funcs[func][DIFF]
								if diff == 0:
									diff = all_funcs[all_funcs[func][PREV_FUNC]][DIFF]
								total_disp = total_disp - all_funcs[func][SIZE] - diff
							if total_disp >= vmaddr + dataoff:
								continue
							elif insn.address < vmaddr + all_funcs[func][ADDR]:
								# blx to stubs
								diff = all_funcs[func][DIFF]
								if diff == 0:
									diff = all_funcs[all_funcs[func][PREV_FUNC]][DIFF]
								total_disp = total_disp - all_funcs[func][SIZE] - diff

						# do not violate the alignment constraint
						pc = (insn.address + pad + 4) & 0xFFFFFFFC
						# current address is pc - 4 for thumb mode
						if pad > 0:
							new_addr = total_disp - pc + 8
						else:
							new_addr = total_disp - pc + 4
						asm_str = insn.mnemonic + " " + hex(new_addr)
						encoding, count = self.ks_thumb_mi.asm(bytes(asm_str))
						new_fn += bytearray(encoding)
				elif is_insn_branch(insn.id) and insn.operands[0].type == ARM_OP_IMM:
					total_disp = insn.operands[0].value.imm + pad - 2
					new_fn += insn.bytes
					continue
					for func in rem_funcs:
						if insn.address > vmaddr + all_funcs[func][ADDR] + all_funcs[func][SIZE]:
							continue
						diff = all_funcs[func][DIFF]
						if diff == 0:
							diff = all_funcs[all_funcs[func][PREV_FUNC]][DIFF]

						if total_disp >= vmaddr + dataoff:
							diff = all_funcs[func][DIFF]
							if diff == 0:
								diff = all_funcs[all_funcs[func][PREV_FUNC]][DIFF]
							total_disp = total_disp - all_funcs[func][SIZE] - diff
						if total_disp >= vmaddr + dataoff:
							continue
						elif insn.address < vmaddr + all_funcs[func][ADDR]:
							# blx to stubs
							diff = all_funcs[func][DIFF]
							if diff == 0:
								diff = all_funcs[all_funcs[func][PREV_FUNC]][DIFF]
							total_disp = total_disp - all_funcs[func][SIZE] - diff

					pc = insn.address + 2
					new_addr = total_disp - pc + 2
					asm_str = insn.mnemonic + " " + hex(new_addr)
					encoding, count = self.ks_thumb_mi.asm(insn.mnemonic + " #" + hex(total_disp), insn.address)
					new_fn += bytearray(encoding)
				else:
					encoding, count = self.ks_thumb_mi.asm(bytes(insn.mnemonic + " " + insn.op_str))
					new_fn += bytearray(encoding)

		return new_fn

	def adjust_stubs(self, stubs, textoff, vmaddr, total_removed):
		new_stubs = bytearray()
		first_addr = None

		b = bytearray()
		b.extend(stubs)

		new_stub_data = []

		for insn in self.cs_arm_mi.disasm(stubs, vmaddr + textoff):
			if self.verbose:
				print("0x%x:\t%s\t%s" % (insn.address, insn.mnemonic, insn.op_str))

			if first_addr is None:
				first_addr = insn.address

			if insn.id == ARM_INS_LDR:
				for i in insn.operands:
					if i.type == ARM_OP_MEM and i.value.reg == ARM_REG_PC:
						new_stub_data.append(insn.address + i.value.mem.disp + 8)

		for new_data in new_stub_data:
			crt_pos = new_data - first_addr
			data = struct.unpack('<I', b[crt_pos:(crt_pos + 4)])[0]
			data += total_removed
			packed = struct.pack('<I', data)
			stubs = stubs[:crt_pos] + packed + stubs[(crt_pos + 4):]

		return stubs

	def adjust_stub_helper(self, stub_helper, vmaddr, helperoff, total_removed):
		new_stub_helper = bytearray()

		first_addr = None
		new_stub_data = []

		b = bytearray()
		b.extend(stub_helper)

		for insn in self.cs_arm_mi.disasm(stub_helper, vmaddr + helperoff):
		 	if self.verbose:
		 		print("0x%x:\t%s\t%s" % (insn.address, insn.mnemonic, insn.op_str))

	 		if first_addr is None:
				first_addr = insn.address

			if insn.id == ARM_INS_LDR:
				for i in insn.operands:
					if i.type == ARM_OP_MEM and i.value.reg == ARM_REG_PC and i.value.mem.disp != 0:
						new_stub_data.append(insn.address + i.value.mem.disp + 8)

		for new_data in new_stub_data:
			crt_pos = new_data - first_addr
			data = struct.unpack('<I', b[crt_pos:(crt_pos + 4)])[0]
			data += total_removed
			packed = struct.pack('<I', data)
			stub_helper = stub_helper[:crt_pos] + packed + stub_helper[(crt_pos + 4):]

		return stub_helper