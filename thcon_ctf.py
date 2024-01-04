import struct
import traceback
import os
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

def getSignedNumber(number, bitLength):
    mask = (2 ** bitLength) - 1
    if number & (1 << (bitLength - 1)):
        return number | ~mask
    else:
        return number & mask

ops = {
	1:    ["ADD ", 'rrr'],
	2:    ["SUB ", 'rrr'],
	3:    ["LSL ",'rrr'],
	4:    ["LSR ",'rrr'],
	5:    ["OR ",'rrr'],
	6:    ["AND ",'rrr'],
	7:    ["CMP ",'rrr'],
	8:    ["CMPAE ",'rrr'], # >=
	9:    ["CMPLE ",'rrr'], # <=
	10:   ["CMPA ",'rrr'], # >
	11:   ["CMPL ",'rrr'], # <
	12:   ["XOR ",'rrr'],
	0xD0: ["MOV ", 'rI'],
	0x0e: ["MUL ", 'rrr'],
	0xc0: ["READ ", ''],
	0xc1: ["WRITE ", ''],
	0xc2: ["OPEN ", ''],
	0xc3: ["EXIT ", ''],
	0xd1: ["MOV ", 'rr'],
	0xe2: ["MOV ", 'rM'], # M = mrI
	0xe3: ["MOV ", 'Mr'],
	0xe4: ["MOV ", 'rm'],
	0xe5: ["MOV ", 'mr'],
	0xF0: ["JMP ", 'jI'],
	0xF1: ["JMP_EQ ", 'jIr'],
	0xF2: ["JUMP ", 'r'],
	0xF3: ["CALL ", 'jI'],
}


class THCON(Architecture):
	name = "THCON"
	address_size = 2
	default_int_size = 2
	instr_alignment = 4
	max_instr_length = 4
	regs = {
        'R0': RegisterInfo('R0', 2),
		'R1': RegisterInfo('R1', 2),
		'R2': RegisterInfo('R2', 2),
		'R3': RegisterInfo('R3', 2),
		'R4': RegisterInfo('R4', 2),
		'R5': RegisterInfo('R5', 2),
		'R6': RegisterInfo('R6', 2),
		'R7': RegisterInfo('R7', 2),
		'R8': RegisterInfo('R8', 2),
		'R9': RegisterInfo('R9', 2),
		'R10': RegisterInfo('R10', 2),
		'R11': RegisterInfo('R11', 2),
		'R12': RegisterInfo('R12', 2),
        'R13': RegisterInfo('R13', 2),
        'R14': RegisterInfo('R14', 2),
	}
	stack_pointer = "R13"
	link_reg = "R14"

	@staticmethod
	def decode_instruction(data:bytes, addr:int):
		if addr >= 0x5758:
			return None
		
		opcode = data[3]
		arg2 = data[2]
		arg1 = data[1]
		arg0 = data[0]

		if opcode in ops:
			text, args = ops[opcode]
			if args == 'rrr':
				return [
					InstructionTextToken(InstructionTextTokenType.TextToken, text),
					InstructionTextToken(InstructionTextTokenType.RegisterToken, f'R{arg2}'),
					InstructionTextToken(InstructionTextTokenType.TextToken, ", "),
					InstructionTextToken(InstructionTextTokenType.RegisterToken, f'R{arg1}'),
					InstructionTextToken(InstructionTextTokenType.TextToken, ", "),
					InstructionTextToken(InstructionTextTokenType.RegisterToken, f'R{arg0}'),		
				]
			elif args == 'rI':
				value = arg0 + arg1 * 0x100
				return [
					InstructionTextToken(InstructionTextTokenType.TextToken, text),
					InstructionTextToken(InstructionTextTokenType.RegisterToken, f'R{arg2}'),
					InstructionTextToken(InstructionTextTokenType.TextToken, ", "),
					InstructionTextToken(InstructionTextTokenType.IntegerToken, f"0x{value:x}", value)	
				]
			elif args == 'rr':
				return [
					InstructionTextToken(InstructionTextTokenType.TextToken, text),
					InstructionTextToken(InstructionTextTokenType.RegisterToken, f'R{arg2}'),
					InstructionTextToken(InstructionTextTokenType.TextToken, ", "),
					InstructionTextToken(InstructionTextTokenType.RegisterToken, f'R{arg1}'),
				]
			elif args == 'rM':
				value = getSignedNumber(arg1,8)
				s = ''
				if value < 0:
					s += '-'
					value = abs(value)
				return [
					InstructionTextToken(InstructionTextTokenType.TextToken, text),
					InstructionTextToken(InstructionTextTokenType.RegisterToken, f'R{arg2}'),
					InstructionTextToken(InstructionTextTokenType.TextToken, ", ["),
					InstructionTextToken(InstructionTextTokenType.RegisterToken, f'R{arg0}'),
					InstructionTextToken(InstructionTextTokenType.TextToken, " + "),
					InstructionTextToken(InstructionTextTokenType.IntegerToken, f"{s}0x{value:04x}", value),
					InstructionTextToken(InstructionTextTokenType.TextToken, "]"),
				]
			elif args == 'Mr':
				value = getSignedNumber(arg2, 8)
				s = ''
				if value < 0:
					s += '-'
					value = abs(value)
				return [
					InstructionTextToken(InstructionTextTokenType.TextToken, text),
					InstructionTextToken(InstructionTextTokenType.TextToken, "["),
					InstructionTextToken(InstructionTextTokenType.RegisterToken, f'R{arg1}'),
					InstructionTextToken(InstructionTextTokenType.TextToken, " + "),
					InstructionTextToken(InstructionTextTokenType.IntegerToken, f"{s}0x{value:04x}", value),
					InstructionTextToken(InstructionTextTokenType.TextToken, "], "),
					InstructionTextToken(InstructionTextTokenType.RegisterToken, f'R{arg0}'),
				]
			elif args == 'rm':
				return [
					InstructionTextToken(InstructionTextTokenType.TextToken, text),
					InstructionTextToken(InstructionTextTokenType.RegisterToken, f'R{arg2}'),
					InstructionTextToken(InstructionTextTokenType.TextToken, ", ["),
					InstructionTextToken(InstructionTextTokenType.RegisterToken, f'R{arg1}'),
					InstructionTextToken(InstructionTextTokenType.TextToken, " + "),
					InstructionTextToken(InstructionTextTokenType.RegisterToken, f'R{arg0}'),
					InstructionTextToken(InstructionTextTokenType.TextToken, "]"),
				]
			elif args == 'mr':
				return [
					InstructionTextToken(InstructionTextTokenType.TextToken, text),
					InstructionTextToken(InstructionTextTokenType.TextToken, "["),
					InstructionTextToken(InstructionTextTokenType.RegisterToken, f'R{arg2}'),
					InstructionTextToken(InstructionTextTokenType.TextToken, " + "),
					InstructionTextToken(InstructionTextTokenType.RegisterToken, f'R{arg1}'),
					InstructionTextToken(InstructionTextTokenType.TextToken, "], "),
					InstructionTextToken(InstructionTextTokenType.RegisterToken, f'R{arg0}'),
				]
			elif args == 'jI':
				value = arg1 + arg2 * 0x100
				return [
					InstructionTextToken(InstructionTextTokenType.TextToken, text),
					InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, f"0x{value:04x}", value),
				]
			elif args == 'jIr':
				value = arg1 + arg2 * 0x100
				return [
					InstructionTextToken(InstructionTextTokenType.TextToken, text),
					InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, f"0x{value:04x}", value),
					InstructionTextToken(InstructionTextTokenType.TextToken, " IF "),
					InstructionTextToken(InstructionTextTokenType.RegisterToken, f'R{arg0}'),
				]
			elif args == 'r':
				return [
					InstructionTextToken(InstructionTextTokenType.TextToken, text),
					InstructionTextToken(InstructionTextTokenType.RegisterToken, f'R{arg2}'),
				]
			elif args == '':
				return [InstructionTextToken(InstructionTextTokenType.TextToken, text)]
				# InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, "$%.4x" % value, value),
		return None

	def get_instruction_info(self, data:bytes, addr:int) -> Optional[InstructionInfo]:
		ins = THCON.decode_instruction(data, addr)
		if not ins:
			return None
		
		result = InstructionInfo()
		result.length = 4
		if data[3] in [0xc0, 0xc1, 0xc2, 0xc3]:
			# result.add_branch(BranchType.SystemCall, data[3])
			if data[3] == 0xc3:
				result.add_branch(BranchType.UnresolvedBranch)
		elif data[3] == 0xF0:
			imm = data[1:3]
			target = struct.unpack("<H",imm)[0]
			result.add_branch(BranchType.UnconditionalBranch, target)
		elif data[3] == 0xF1:
			imm = data[1:3]
			target = struct.unpack("<H",imm)[0]
			result.add_branch(BranchType.TrueBranch, target)
			result.add_branch(BranchType.FalseBranch, addr + 4)
		elif data[3] == 0xf2:
			if data[2] == 14:
				result.add_branch(BranchType.FunctionReturn)
			else:
				print(f'0x{addr:x} INDIRECT WITH {data[2]}')
				result.add_branch(BranchType.UnresolvedBranch)
		elif data[3] == 0xf3:
			imm = data[1:3]
			target = struct.unpack("<H",imm)[0]
			result.add_branch(BranchType.CallDestination, target)
		return result


	def get_instruction_text(self, data: bytes, addr: int) -> Optional[Tuple[List[InstructionTextToken], int]]:
		ins = THCON.decode_instruction(data, addr)
		return ins, 4


	def get_instruction_low_level_il(self, data: bytes, addr: int, il: LowLevelILFunction) -> Optional[int]:
		op = data[3]
		arg2 = data[2]
		arg1 = data[1]
		arg0 = data[0]
		reg2 = RegisterName(f"R{arg2}")
		reg1 = RegisterName(f"R{arg1}")
		reg0 = RegisterName(f"R{arg0}")
		i = None
		if op == 1:
			i = il.set_reg(2, reg2, il.add(2, il.reg(2, reg1), il.reg(2, reg0)))
		elif op == 2:
			i = il.set_reg(2, reg2, il.sub(2, il.reg(2, reg1), il.reg(2, reg0)))
		elif op == 3:
			i = il.set_reg(2, reg2, il.shift_left(2, il.reg(2, reg1), il.reg(2, reg0)))
		elif op == 4:
			i = il.set_reg(2, reg2, il.logical_shift_right(2, il.reg(2, reg1), il.reg(2, reg0)))
		elif op == 4:
			i = il.set_reg(2, reg2, il.logical_shift_right(2, il.reg(2, reg1), il.reg(2, reg0)))
		elif op == 5:
			i = il.set_reg(2, reg2, il.or_expr(2, il.reg(2, reg1), il.reg(2, reg0)))
		elif op == 6:
			i = il.set_reg(2, reg2, il.and_expr(2, il.reg(2, reg1), il.reg(2, reg0)))
		elif op == 7:
			i = il.set_reg(2, reg2, il.compare_equal(2, il.reg(2, reg1), il.reg(2, reg0)))
		elif op == 8:
			i = il.set_reg(2, reg2, il.compare_unsigned_less_equal(2, il.reg(2, reg1), il.reg(2, reg0)))
		elif op == 9:
			i = il.set_reg(2, reg2, il.compare_unsigned_greater_equal(2, il.reg(2, reg1), il.reg(2, reg0)))
		elif op == 10:
			i = il.set_reg(2, reg2, il.compare_unsigned_less_than(2, il.reg(2, reg1), il.reg(2, reg0)))
		elif op == 11:
			i = il.set_reg(2, reg2, il.compare_unsigned_greater_than(2, il.reg(2, reg1), il.reg(2, reg0)))
		elif op == 12:
			i = il.set_reg(2, reg2, il.xor_expr(2, il.reg(2, reg1), il.reg(2, reg0)))
		elif op == 0xD0:
			imm = struct.unpack("<H",data[:2])[0]
			i = il.set_reg(2, reg2, il.const(2, imm))
		elif op == 0x0e:
			i = il.set_reg(2, reg2, il.mult(2, il.reg(2, reg1), il.reg(2, reg0)))
		elif op in [0xc0, 0xc1, 0xc2]:
			i = il.system_call()
		elif op == 0xc3:
			i = il.no_ret()
		elif op == 0xd1:
			i = il.set_reg(2, reg2, il.reg(2, reg1))
		elif op == 0xe2:
			i = il.set_reg(2, reg2, il.load(2, il.add(2, il.reg(2, reg0), il.const(2, getSignedNumber(arg1, 8)))))
		elif op == 0xe3:
			i = il.store(2, il.add(2, il.reg(2, reg1), il.const(2, getSignedNumber(arg2, 8))), il.reg(2, reg0))
		elif op == 0xe4:
			i = il.set_reg(2, reg2, il.load(2, il.add(2, il.reg(2, reg0), il.reg(2, reg1))))
		elif op == 0xe5:
			i = il.store(2, il.add(2, il.reg(2, reg1), il.reg(2, reg2)), il.reg(2, reg0))
		elif op == 0xF0:
			imm = struct.unpack("<H",data[1:3])[0]
			i = il.jump(il.const_pointer(2, imm))
		elif op == 0xF1:
			imm = struct.unpack("<H",data[1:3])[0]
			t = LowLevelILLabel()                            # step 2
			f = LowLevelILLabel()
			cmp = il.compare_equal(2, il.reg(2, reg0), il.const(2,0))
			il.append(il.if_expr(cmp, t, f))          # step 3
			il.mark_label(t)                                 # step 4
			il.append(il.jump(il.const_pointer(2, imm)))                                 # step 5
			il.mark_label(f)                                 # step 6
			i = il.nop()
		elif op == 0xF2:
			if arg2 != 14:
				print("BAD REGISTER")
				1/0
			i = il.ret(il.reg(2, reg2))
		elif op == 0xF3:
			imm = struct.unpack("<H",data[1:3])[0]
			i = il.call(il.const_pointer(2, imm))
		else:
			return None
		il.append(i)
		return 4

THCON.register()