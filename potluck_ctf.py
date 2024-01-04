import struct
import traceback
import os
from struct import unpack
from typing import Callable, List, Type, Optional, Dict, Tuple, NewType

from binaryninja.architecture import Architecture, InstructionInfo, RegisterInfo, RegisterName, FlagName, FlagWriteTypeName, FlagType
from binaryninja.lowlevelil import LowLevelILLabel, LLIL_TEMP, ExpressionIndex, LowLevelILFunction, ILRegisterType, LowLevelILConst, LowLevelILInstruction
from binaryninja.function import InstructionTextToken
from binaryninja.binaryview import BinaryView
from binaryninja.types import Symbol
from binaryninja.log import log_error
from binaryninja.enums import (
  BranchType, InstructionTextTokenType, LowLevelILOperation, LowLevelILFlagCondition, FlagRole, SegmentFlag, SymbolType
)
from binaryninja.callingconvention import CallingConvention

def getSignedNumber(number, bitLength):
    mask = (2 ** bitLength) - 1
    if number & (1 << (bitLength - 1)):
        return number | ~mask
    else:
        return number & mask


def rname(idx):
	if idx < 8:
		return f"R{idx}"
	elif idx == 8:
		return "SP"
	elif idx == 9:
		return "LR"
	assert False, "BUG"

class POTLUCK(Architecture):
	name = "POTLUCK"
	address_size = 4
	default_int_size = 4
	instr_alignment = 4
	max_instr_length = 4
	flags = ['eq', 'l', 'g', 'le', 'ge']
	#         1     4    2    8     10
	regs = {
        'R0': RegisterInfo('R0', 4),
		'R1': RegisterInfo('R1', 4),
		'R2': RegisterInfo('R2', 4),
		'R3': RegisterInfo('R3', 4),
		'R4': RegisterInfo('R4', 4),
		'R5': RegisterInfo('R5', 4),
		'R6': RegisterInfo('R6', 4),
		'R7': RegisterInfo('R7', 4),
		'SP': RegisterInfo('SP', 4),
		'LR': RegisterInfo('LR', 4),
		'ID': RegisterInfo('ID', 4), # system call id
	}
	stack_pointer = "SP"
	link_reg = "LR"

	@staticmethod
	def decode_instruction(data:bytes, addr:int):
		opcode = data[0]
		arg1 = data[1]
		arg2_h = data[3]
		arg2_l = data[2]
		arg2 = arg2_l + (arg2_h << 8)
		sarg2 = getSignedNumber(arg2, 16)
		sign = ''
		abs_arg2 = sarg2
		if sarg2 < 0:
			sign += '-'
			abs_arg2 = abs(sarg2)

		saddr = addr + sarg2

		smov = {1: 'b ', 2: 'h ', 4:'d ', 8: ' '}

		if opcode == 0:
			return [
				InstructionTextToken(InstructionTextTokenType.TextToken, "nop")
			]
		elif opcode == 1:
			if arg1 == 0:
				txt = 'jmp '
			else:
				txt = 'jmpif '
			return [
				InstructionTextToken(InstructionTextTokenType.TextToken, txt),
				InstructionTextToken(InstructionTextTokenType.IntegerToken, f"0x{saddr:08x}"),
			]
		elif opcode == 2:
			return [
				InstructionTextToken(InstructionTextTokenType.TextToken, "mov" + smov[arg1]),
				InstructionTextToken(InstructionTextTokenType.RegisterToken, f'R{arg2_l}'),
				InstructionTextToken(InstructionTextTokenType.TextToken, ", ["),
				InstructionTextToken(InstructionTextTokenType.RegisterToken, f'R{arg2_h}'),
				InstructionTextToken(InstructionTextTokenType.TextToken, "]"),
			]
		elif opcode == 3:
			return [
				InstructionTextToken(InstructionTextTokenType.TextToken, "mov" + smov[arg1]),
				InstructionTextToken(InstructionTextTokenType.TextToken, "["),
				InstructionTextToken(InstructionTextTokenType.RegisterToken, f'R{arg2_h}'),
				InstructionTextToken(InstructionTextTokenType.TextToken, "], "),
				InstructionTextToken(InstructionTextTokenType.RegisterToken, f'R{arg2_l}'),
			]
		elif opcode == 4:
			op = {0: 'add ', 1: 'sub ', 2:'mul ', 3:'div ', 4:'and ', 5:'or ', 6:'xor ', 7:'lshf ', 8:'rshf '}
			if arg1 & 0xf:
				return [
					InstructionTextToken(InstructionTextTokenType.TextToken, op[arg1 >> 4]),
					InstructionTextToken(InstructionTextTokenType.RegisterToken, f'R{arg2_l}'),
					InstructionTextToken(InstructionTextTokenType.TextToken, ", "),
					InstructionTextToken(InstructionTextTokenType.IntegerToken, f'0x{arg2_h:x}'),
				]
			else:
				return [
					InstructionTextToken(InstructionTextTokenType.TextToken, op[arg1 >> 4]),
					InstructionTextToken(InstructionTextTokenType.RegisterToken, f'R{arg2_l}'),
					InstructionTextToken(InstructionTextTokenType.TextToken, ", "),
					InstructionTextToken(InstructionTextTokenType.RegisterToken, f'R{arg2_h}'),
				]
		elif opcode == 5:
			return [
				InstructionTextToken(InstructionTextTokenType.TextToken, "syscall "),
				InstructionTextToken(InstructionTextTokenType.IntegerToken, f'0x{arg1:x}'),
			]
		elif opcode == 6:
			if arg1 >> 4 == 1:
				return [
					InstructionTextToken(InstructionTextTokenType.TextToken, "cmp "),
					InstructionTextToken(InstructionTextTokenType.RegisterToken, f'R{arg2_l}'),
					InstructionTextToken(InstructionTextTokenType.TextToken, ", "),
					InstructionTextToken(InstructionTextTokenType.IntegerToken, f'0x{arg2_h:x}'),
				]
			else:
				return [
					InstructionTextToken(InstructionTextTokenType.TextToken, "cmp "),
					InstructionTextToken(InstructionTextTokenType.RegisterToken, f'R{arg2_h}'),
					InstructionTextToken(InstructionTextTokenType.TextToken, ", "),
					InstructionTextToken(InstructionTextTokenType.RegisterToken, f'R{arg2_l}'),
				]
		elif opcode == 7:
			if arg1 & 0xf:
				return [
					InstructionTextToken(InstructionTextTokenType.TextToken, "mov "),
					InstructionTextToken(InstructionTextTokenType.RegisterToken, f'R{(arg1 >> 4)}'),
					InstructionTextToken(InstructionTextTokenType.TextToken, ", "),
					InstructionTextToken(InstructionTextTokenType.IntegerToken, f"{sign}0x{abs_arg2:08x}"),
				]
			else:
				return [
					InstructionTextToken(InstructionTextTokenType.TextToken, "mov "),
					InstructionTextToken(InstructionTextTokenType.RegisterToken, f'R{(arg1 >> 4)}'),
					InstructionTextToken(InstructionTextTokenType.TextToken, ", "),
					InstructionTextToken(InstructionTextTokenType.RegisterToken, f'R{arg2_l}'),
				]
		elif opcode == 8:
			return [
				InstructionTextToken(InstructionTextTokenType.TextToken, "push "),
				InstructionTextToken(InstructionTextTokenType.RegisterToken, f'R{arg1}'),
			]
		elif opcode == 9:
			return [
				InstructionTextToken(InstructionTextTokenType.TextToken, "pop "),
				InstructionTextToken(InstructionTextTokenType.RegisterToken, f'R{arg1}'),
			]
		elif opcode == 10:
			if arg1 == 1:
				return [
					InstructionTextToken(InstructionTextTokenType.TextToken, "call "),
					InstructionTextToken(InstructionTextTokenType.RegisterToken, f'R{arg2_h}'),
				]
			else:
				return [
					InstructionTextToken(InstructionTextTokenType.TextToken, "call "),
					InstructionTextToken(InstructionTextTokenType.IntegerToken, f"0x{saddr:08x}"),
				]
		elif opcode == 12:
			return [
				InstructionTextToken(InstructionTextTokenType.TextToken, "ret")
			]

		return None

	def get_instruction_info(self, data:bytes, addr:int) -> Optional[InstructionInfo]:
		ins = POTLUCK.decode_instruction(data, addr)
		if not ins:
			return None
		
		arg1 = data[1]
		arg2_h = data[3]
		arg2_l = data[2]
		arg2 = arg2_l + (arg2_h << 8)
		sarg2 = getSignedNumber(arg2, 16)

		result = InstructionInfo()
		result.length = 4
		if data[0] == 5:
			result.add_branch(BranchType.SystemCall, arg1)
		elif data[0] == 1:
			if data[1] == 0:
				result.add_branch(BranchType.UnconditionalBranch, addr + sarg2)
			else:
				result.add_branch(BranchType.TrueBranch, addr + sarg2)
				result.add_branch(BranchType.FalseBranch, addr + 4)
		elif data[0] == 10:
			if arg1 == 1:
				result.add_branch(BranchType.IndirectBranch)
			else:
				result.add_branch(BranchType.CallDestination, addr + sarg2)
		elif data[0] == 12:
			result.add_branch(BranchType.FunctionReturn)
		return result



	def get_instruction_text(self, data: bytes, addr: int) -> Optional[Tuple[List[InstructionTextToken], int]]:
		ins = POTLUCK.decode_instruction(data, addr)
		return ins, 4


	def get_instruction_low_level_il(self, data: bytes, addr: int, il: LowLevelILFunction) -> Optional[int]:
		opcode = data[0]
		arg1 = data[1]
		arg2_h = data[3]
		arg2_l = data[2]
		arg2 = arg2_l + (arg2_h << 8)
		sarg2 = getSignedNumber(arg2, 16)
		sign = ''
		abs_arg2 = sarg2
		if sarg2 < 0:
			sign += '-'
			abs_arg2 = abs(sarg2)

		saddr = addr + sarg2

		if opcode == 0:
			i = il.nop()
		elif opcode == 1:

			if arg1 == 0:
				i = il.append(il.jump(il.const_pointer(4, saddr)))
			else:
				t = LowLevelILLabel()
				f = LowLevelILLabel()
				flags_ = {
					3: 'eq', 
			  		6: 'eq', # not eq
					1: 'l',
					4: 'le',
					2: 'g',
					5: 'ge',
				}
				if arg1 == 6:
					il.append(il.if_expr(il.flag(flags_[arg1]), f, t))
				else:
					il.append(il.if_expr(il.flag(flags_[arg1]), t, f))
				il.mark_label(t)
				il.append(il.jump(il.const_pointer(4, saddr)))
				il.mark_label(f)
				i = il.nop()
		elif opcode == 2:
			dst = RegisterName(rname(arg2_l))
			src = RegisterName(rname(arg2_h))
			i = il.set_reg(4, dst, il.load(arg1, il.reg(4, src)))
		elif opcode == 3:
			dst = RegisterName(rname(arg2_h))
			src = RegisterName(rname(arg2_l))
			i = il.store(arg1, il.reg(4, dst), il.reg(4, src))
		elif opcode == 4:
			op = arg1 >> 4
			dst = RegisterName(rname(arg2_l))
			src = il.const(4, arg2_h)
			if (arg1 & 0xf) == 0:
				src = il.reg(4, RegisterName(rname(arg2_h)))
			if op == 0:
				i = il.set_reg(4, dst, il.add(4, il.reg(4, dst), src))
			elif op == 1:
				i = il.set_reg(4, dst, il.sub(4, il.reg(4, dst), src))
			elif op == 2:
				i = il.set_reg(4, dst, il.mult(4, il.reg(4, dst), src))
			elif op == 3:
				i = il.set_reg(4, dst, il.div_unsigned(4, il.reg(4, dst), src))
			elif op == 4:
				i = il.set_reg(4, dst, il.and_expr(4, il.reg(4, dst), src))
			elif op == 5:
				i = il.set_reg(4, dst, il.or_expr(4, il.reg(4, dst), src))
			elif op == 6:
				i = il.set_reg(4, dst, il.xor_expr(4, il.reg(4, dst), src))
			elif op == 7:
				i = il.set_reg(4, dst, il.shift_left(4, il.reg(4, dst), src))
			elif op == 8:
				i = il.set_reg(4, dst, il.logical_shift_right(4, il.reg(4, dst), src))
		elif opcode == 5:
			il.append(il.set_reg(4, RegisterName('ID'), il.const(4, arg1)))
			i = il.system_call()
			'''
				0 stop
				1 putc
				2 getc
				3 write to socket
				4 read from socket
				5 prng
				7 uptime
			'''
		elif opcode == 6:
			
			if arg1 >> 4 == 1:
				r1 = RegisterName(rname(arg2_l))
				il.append(il.set_flag('le', il.compare_unsigned_less_equal(4, il.reg(4, r1), il.const(4, arg2_h))))
				il.append(il.set_flag('ge', il.compare_unsigned_greater_equal(4, il.reg(4, r1), il.const(4, arg2_h))))
				il.append(il.set_flag('g', il.compare_unsigned_greater_than(4, il.reg(4, r1), il.const(4, arg2_h))))
				il.append(il.set_flag('l', il.compare_unsigned_less_than(4, il.reg(4, r1), il.const(4, arg2_h))))
				i = il.set_flag('eq', il.compare_equal(4, il.reg(4, r1), il.const(4, arg2_h)))
			else:
				r1 = RegisterName(rname(arg2_h))
				r2 = RegisterName(rname(arg2_l))
				il.append(il.set_flag('le', il.compare_unsigned_less_equal(4, il.reg(4, r1), il.reg(4, r2))))
				il.append(il.set_flag('ge', il.compare_unsigned_greater_equal(4, il.reg(4, r1), il.reg(4, r2))))
				il.append(il.set_flag('g', il.compare_unsigned_greater_than(4, il.reg(4, r1), il.reg(4, r2))))
				il.append(il.set_flag('l', il.compare_unsigned_less_than(4, il.reg(4, r1), il.reg(4, r2))))
				i = il.set_flag('eq', il.compare_equal(4, il.reg(4, r1), il.reg(4, r2)))
		elif opcode == 7:
			dst = RegisterName(rname(arg1 >> 4 ))
			if arg1 & 0xf:
				i = il.set_reg(4, dst, il.const(4, sarg2))
			else:
				r2 = RegisterName(rname(arg2_l))
				i = il.set_reg(4, dst, il.reg(4, r2))
		elif opcode == 8:
			r1 = RegisterName(rname(arg1))
			i = il.push(4, il.reg(4, r1))
		elif opcode == 9:
			r1 = RegisterName(rname(arg1))
			i = il.set_reg(4, r1, il.pop(4))
		elif opcode == 10:
			if arg1 == 1:
				r2 = RegisterName(rname(arg2_h))
				i = il.call(il.reg(4, r2))
			else:
				i = il.call(il.const_pointer(4, saddr))
		elif opcode == 12:
			i = il.ret(il.reg(4, RegisterName(f"LR")))
		else:
			return None
		il.append(i)
		return 4

POTLUCK.register()

class CustomSyscall(CallingConvention):
    int_arg_regs = ['ID', 'R0', 'R1']
    int_return_reg = 'R0'
    eligible_for_heuristics = False

class POTLUCKView(BinaryView):
	name = 'POTLUCKView'
	long_name = 'POTLUCKView ROM'

	def __init__(self, data):
		# data is a binaryninja.binaryview.BinaryView
		BinaryView.__init__(self, parent_view = data, file_metadata = data.file)
		self.platform = Architecture['POTLUCK'].standalone_platform
		convention = CallingConvention(Architecture['POTLUCK'], 'customConvention')
		convention.int_arg_regs = ['R0', 'R1', 'R2', 'R3']
		convention.int_return_reg = 'R0'
		system_call_convention = CallingConvention(Architecture['POTLUCK'], 'customConvention2')
		system_call_convention.int_arg_regs = ['ID', 'R0', 'R1']
		system_call_convention.int_return_reg = 'R0'
		self.platform.convention = convention
		Architecture['POTLUCK'].register_calling_convention(convention)
		Architecture['POTLUCK'].standalone_platform.default_calling_convention = convention
		cc_sys = CustomSyscall(arch=Architecture['POTLUCK'], name='CustomSyscall')
		Architecture['POTLUCK'].register_calling_convention(cc_sys)
		Architecture['POTLUCK'].system_call_convention = cc_sys
		self.platform.register_calling_convention(cc_sys)
		self.platform.system_call_convention = cc_sys
		self.data = data

	@classmethod
	def is_valid_for_data(self, data):
		header = data.read(0, 7)
		return header == b'UNICORN'

	def perform_get_address_size(self):
		return 8

	def init(self):
		count = unpack("<H", self.data.read(0x8, 2))[0]
		print(f"segment count = {count}")
		for i in range(count):
			base = unpack("<H", self.data.read(0xa + 6 * i, 2))[0]
			size = unpack("<H", self.data.read(0xa + 2 + 6 * i, 2))[0]
			prot = unpack("<H", self.data.read(0xa + 2 + 2 + 6 * i, 2))[0]
			print(f"segment 0x{base:x} len 0x{size:x} prot {prot}")
			if i == 0:
				self.add_auto_segment(base, size, 0xa + 6 * count, size, SegmentFlag.SegmentReadable|SegmentFlag.SegmentExecutable)
			else:
				self.add_auto_segment(base, size, 0, 0, SegmentFlag.SegmentReadable|SegmentFlag.SegmentWritable)
				self.write(base, b'\x00' * size)

		self.add_entry_point(0)
		return True
	
	def perform_is_executable(self):
		return True

	def perform_get_entry_point(self):
		return 0

POTLUCKView.register()
