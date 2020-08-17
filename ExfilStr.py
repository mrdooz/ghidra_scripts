from ghidra.program.model.lang import OperandType
from ghidra.program.model.symbol import RefType

#TODO write a description for this script
#@author 
#@category CustomerSubmission
#@keybinding 
#@menupath 
#@toolbar 


#TODO Add User Code Here

# listing = currentProgram.getListing()

# getInstructionAt

def operand_str(n):
	res = []
	if n & OperandType.READ: res.append('READ')
	if n & OperandType.WRITE: res.append('WRITE')
	if n & OperandType.INDIRECT: res.append('INDIRECT')
	if n & OperandType.IMMEDIATE: res.append('IMMEDIATE')
	if n & OperandType.RELATIVE: res.append('RELATIVE')
	if n & OperandType.IMPLICIT: res.append('IMPLICIT')
	if n & OperandType.CODE: res.append('CODE')
	if n & OperandType.DATA: res.append('DATA')
	if n & OperandType.PORT: res.append('PORT')
	if n & OperandType.REGISTER: res.append('REGISTER')
	if n & OperandType.LIST: res.append('LIST')
	if n & OperandType.FLAG: res.append('FLAG')
	if n & OperandType.TEXT: res.append('TEXT')
	if n & OperandType.ADDRESS: res.append('ADDRESS')
	if n & OperandType.SCALAR: res.append('SCALAR')
	if n & OperandType.BIT: res.append('BIT')
	if n & OperandType.BYTE: res.append('BYTE')
	if n & OperandType.WORD: res.append('WORD')
	if n & OperandType.QUADWORD: res.append('QUADWORD')
	if n & OperandType.SIGNED: res.append('SIGNED')
	if n & OperandType.FLOAT: res.append('FLOAT')
	if n & OperandType.COP: res.append('COP')
	if n & OperandType.DYNAMIC: res.append('DYNAMIC')
	return res

def dec(s):
	try:
		cc = [chr(b - ord('X')) for b in s]
		return ''.join(cc)
	except:
		print("error decoding: %s" % str(s))

def process_instruction(ins, write_bytes):
	print(ins)
	ctx = ins.getInstructionContext()
	proto = ins.getPrototype()
	num_operands = proto.getNumOperands()
	if num_operands == 2:
		dst_ref_type = ins.getOperandRefType(0)
		dst_type = ins.getOperandType(0)
		src_ref_type = ins.getOperandRefType(1)
		src_type = ins.getOperandType(1)

		if dst_ref_type == RefType.WRITE and dst_type & OperandType.ADDRESS and src_type & OperandType.SCALAR:
			addr = proto.getAddress(0, ctx)
			scalar = proto.getScalar(1, ctx)
			bs = []
			for b in scalar.byteArrayValue()[::-1]:
				if b < 0:
					bs.append(0x100 + b)
				else:
					bs.append(b)
			write_bytes += bs



def get_write_bytes_in_sel(sel):
	write_bytes = []

	ip = currentSelection.getMinAddress()
	ins = getInstructionAt(ip)

	while sel.contains(ins.getAddress()):
		process_instruction(ins, write_bytes)
		ins = ins.getNext()
	return write_bytes

def print_bytes(b):
	try:
		print(''.join(chr(x) for x in b))
	except:
		pass
	print(', '.join([hex(x) for x in b]))

def writes_in_function():
	write_bytes = []
	func = getFunctionContaining(currentAddress)
	ins = getInstructionAt(currentAddress)
	while getFunctionContaining(ins.address) == func:
		process_instruction(ins, write_bytes)
		ins = ins.getNext()
	return write_bytes

if currentSelection:
	start = currentSelection.getMinAddress()
	end = currentSelection.getMaxAddress()
	ip = currentSelection.getMinAddress()
	ins = getInstructionAt(ip)
	print(dir(start))
	
	write_bytes = get_write_bytes_in_sel(currentSelection)
	print_bytes(write_bytes)
else:
	write_bytes = writes_in_function()
	print_bytes(write_bytes)
