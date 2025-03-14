#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// TEMP
#include <string>

typedef unsigned char b8;

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;

typedef char i8;
typedef short i16;
typedef int i32;
typedef long long i64;

#define ABS(x) (((x) < 0) ? (-(x)) : (x))
#define SIGN(x) (((x) < 0) ? (-1) : (1))

void* allocate_memory(u64 size) {
	void* ptr = NULL;
	while (ptr == NULL) ptr = malloc(size);
	return ptr;
}

struct RawMemory {
	u8* data;
	u64 size;
};

RawMemory read_file(const char* path, u32 zero_bytes)
{
	FILE* file = fopen(path, "r");
	if (file == NULL) return {};

	RawMemory memory;

	fseek(file, 0, SEEK_END);
	memory.size = ftell(file);
	fseek(file, 0, SEEK_SET);
	memory.data = (u8*)allocate_memory(memory.size + zero_bytes);
	fread(memory.data, 1, memory.size, file);

	memset(memory.data + memory.size, 0, zero_bytes);

	fclose(file);
	return memory;
}

#define RegisterIndex_AX 0
#define RegisterIndex_CX 1
#define RegisterIndex_DX 2
#define RegisterIndex_BX 3
#define RegisterIndex_SP 4
#define RegisterIndex_BP 5
#define RegisterIndex_SI 6
#define RegisterIndex_DI 7
#define RegisterIndex_CS 8
#define RegisterIndex_DS 9
#define RegisterIndex_SS 10
#define RegisterIndex_ES 11

#define RegisterIndex_AH 0
#define RegisterIndex_AL 1
#define RegisterIndex_CH 2
#define RegisterIndex_CL 3
#define RegisterIndex_DH 4
#define RegisterIndex_DL 5
#define RegisterIndex_BH 6
#define RegisterIndex_BL 7

#define RegisterFlag_OF 11 // Overflow
#define RegisterFlag_DF 10 // Direction
#define RegisterFlag_IF 9 // Interrupt
#define RegisterFlag_TF 8 // Trap
#define RegisterFlag_SF 7 // Sign
#define RegisterFlag_ZF 6 // Zero
#define RegisterFlag_AF 4 // Aux Parity
#define RegisterFlag_PF 2 // Parity
#define RegisterFlag_CF 0 // Carry

struct CPU 
{
	union {
		u16 w[12];
		struct {
			u16 ax, cx, dx, bx;
			u16 sp, bp, si, di;
			u16 cs, ds, ss, es;
		};

		u8 b[8];
		struct {
			u8 ah, al;
			u8 ch, cl;
			u8 dh, dl;
			u8 bh, bl;
		};
	} reg;
	u16 flags;
	u16 ip; // Instruction Pointer
	u32 program_size;

	u32 clocks;

	struct {
		b8 print_decoding;
		b8 print_instruction_info;
		b8 print_clocks;
	} debug;

	u8* memory;
};

enum OperationType {
	OperationType_None,
	OperationType_Unknown,
	OperationType_Mov,
	OperationType_Arithmetic,
	OperationType_Jump,
};

enum ArithmeticType {
	ArithmeticType_None,
	ArithmeticType_Add,
	ArithmeticType_Sub,
	ArithmeticType_Cmp,
};

enum JumpType {
	JumpType_None,
	JumpType_Equals,
	JumpType_Lesser,
	JumpType_LesserEquals,
	JumpType_Greater,
	JumpType_GreaterEquals,
	JumpType_Parity,
	JumpType_Overflow,
	JumpType_Sign,
};

enum MemoryType {
	MemoryType_Register,
	MemoryType_EffectiveAddress,
	MemoryType_Immediate,
};

struct InstructionMemory {
	MemoryType type;
	union {
		struct {
			u8 index;
			b8 word;
		} reg;
		struct {
			i32 value;
			b8 word;
		} immediate;
		struct {
			u8 reg_count;
			u8 reg0;
			u8 reg1;
			i32 displacement;
		} address;
	};
};

struct InstructionData {
	OperationType operation_type;

	union {
		ArithmeticType arithmetic_type;
		struct {
			JumpType type;
			b8 negation;
			u8 displacement;
		} jump;
	};
	InstructionMemory dst, src;
};

static CPU cpu;

void cpu_initialize()
{
	cpu = {};
	cpu.memory = (u8*)allocate_memory(1 << 20);
}

b8 cpu_load_program(const char* path)
{
	RawMemory file = read_file(path, 0);

	if (file.size == 0) {
		printf("Not found: %s\n", path);
		return 0;
	}
	
	memcpy(cpu.memory, file.data, file.size);
	cpu.program_size = file.size;
	cpu.ip = 0;

	return 1;
}

u8 program_read_byte() {
	if (cpu.ip >= cpu.program_size) return 0;
	return cpu.memory[cpu.ip++];
}

u16 program_read_word() {
	if (cpu.ip + 2 > cpu.program_size) return 0;
	u16 word = *((u16*)(cpu.memory + cpu.ip));
	cpu.ip += 2;
	return word;
}

b8 program_finished() {
	return cpu.ip >= cpu.program_size;
}

void cpu_crash() {
	printf("Crash!!\n");
	cpu.ip = (u32)cpu.program_size;
}

const char* register_name_table_byte[] = {
	"al", "cl", "dl", "bl",
	"ah", "ch", "dh", "bh",
};

const char* register_name_table_word[] = {
	"ax", "cx", "dx", "bx",
	"sp", "bp", "si", "di",
};

const char* get_register_name(u8 reg, b8 word) {
	if (word) return register_name_table_word[reg];
	else return register_name_table_byte[reg];
}

std::string format_instruction_memory(InstructionMemory mem)
{
	if (mem.type == MemoryType_Register) {
		return get_register_name(mem.reg.index, mem.reg.word);
	}

	if (mem.type == MemoryType_Immediate) {
		std::string str = mem.immediate.word ? "word " : "byte ";
		str += std::to_string(mem.immediate.value);
		return str;
	}

	std::string str = "[";

	if (mem.address.reg_count == 0) {
		str += std::to_string(mem.address.displacement);
	}
	else
	{
		if (mem.address.reg_count == 1) {
			str += get_register_name(mem.address.reg0, 1);
		}
		else if (mem.address.reg_count == 2) {
			str += get_register_name(mem.address.reg0, 1);
			str += " + ";
			str += get_register_name(mem.address.reg1, 1);
		}

		if (mem.address.displacement != 0) {
			str += " ";
			str += (mem.address.displacement > 0) ? "+" : "-";
			str += " ";
			str += std::to_string(ABS(mem.address.displacement));
		}
	}

	str += "]";
	return str;
}

const char* get_arithmetic_operation_name(ArithmeticType op) {
	if (op == ArithmeticType_Add) return "add";
	if (op == ArithmeticType_Sub) return "sub";
	if (op == ArithmeticType_Cmp) return "cmp";
	return "?";
}

const char* get_jump_name(JumpType jmp, b8 negation) {
	if (jmp == JumpType_Equals) return negation ? "jne" : "je";
	else if (jmp == JumpType_Lesser) return negation ? "jnl" : "jl";
	else if (jmp == JumpType_LesserEquals) return negation ? "jnle" : "jle";
	else if (jmp == JumpType_Greater) return negation ? "jnb" : "jb";
	else if (jmp == JumpType_GreaterEquals) return negation ? "jnbe" : "jbe";
	else if (jmp == JumpType_Parity) return negation ? "jnp" : "jp";
	else if (jmp == JumpType_Overflow) return negation ? "jno" : "jo";
	else if (jmp == JumpType_Sign) return negation ? "jns" : "js";
	return "?";
}

void print_decoding(InstructionData inst)
{
	switch (inst.operation_type)
	{

	case OperationType_Mov:
	{
		std::string src_name = format_instruction_memory(inst.src);
		std::string dst_name = format_instruction_memory(inst.dst);

		printf("mov %s, %s\n", dst_name.c_str(), src_name.c_str());
	} break;
	
	case OperationType_Arithmetic:
	{
		const char* op = get_arithmetic_operation_name(inst.arithmetic_type);

		std::string src_name = format_instruction_memory(inst.src);
		std::string dst_name = format_instruction_memory(inst.dst);

		printf("%s %s, %s\n", op, dst_name.c_str(), src_name.c_str());
	} break;

	case OperationType_Jump:
	{
		const char* jmp = get_jump_name(inst.jump.type, inst.jump.negation);
		printf("%s ; %i\n", jmp, (i32)inst.jump.displacement);
	} break;

	case OperationType_Unknown:
	default:
		printf("Unknwon instruction decoding\n");
		break;
	}

	if (inst.operation_type == OperationType_Mov) {

	}
}

InstructionMemory memory_from_register(u8 reg, b8 w) {
	InstructionMemory mem{};
	mem.type = MemoryType_Register;
	mem.reg.index = reg;
	mem.reg.word = w;
	return mem;
}

static void set_effective_address_registers(InstructionMemory* mem, u8 rm)
{
	if (rm == 0b000) { mem->address.reg_count = 2; mem->address.reg0 = RegisterIndex_BX; mem->address.reg1 = RegisterIndex_SI; }
	else if (rm == 0b001) { mem->address.reg_count = 2; mem->address.reg0 = RegisterIndex_BX; mem->address.reg1 = RegisterIndex_DI; }
	else if (rm == 0b010) { mem->address.reg_count = 2; mem->address.reg0 = RegisterIndex_BP; mem->address.reg1 = RegisterIndex_SI; }
	else if (rm == 0b011) { mem->address.reg_count = 2; mem->address.reg0 = RegisterIndex_BP; mem->address.reg1 = RegisterIndex_DI; }
	else if (rm == 0b100) { mem->address.reg_count = 1; mem->address.reg0 = RegisterIndex_SI; }
	else if (rm == 0b101) { mem->address.reg_count = 1; mem->address.reg0 = RegisterIndex_DI; }
	else if (rm == 0b110) { mem->address.reg_count = 1; mem->address.reg0 = RegisterIndex_BP; }
	else if (rm == 0b111) { mem->address.reg_count = 1; mem->address.reg0 = RegisterIndex_BX; }
	else {
		printf("Invalid RM field %i\n", (i32)rm);
	}
}

InstructionMemory memory_from_direct_address(b8 w)
{
	InstructionMemory mem{};
	mem.type = MemoryType_EffectiveAddress;
	mem.address.reg_count = 0;
	i32 v = 0;
	if (w) v = (i32)program_read_word();
	else v = (i32)program_read_byte();
	mem.address.displacement = v;
	return mem;
}

InstructionMemory memory_from_rm_field(u8 rm, u8 mod, b8 w)
{
	InstructionMemory mem{};

	// mod: Indicates where are the operands: In memory or in registers
	//			00 = Memory mode, no displacement follows
	//			01 = Memory mode, 8 bit displacement follows
	//			10 = Memory mode, 16 bit displacement follows
	//			11 = Register mode (no displacement)

	if (mod == 0b11) return memory_from_register(rm, w);

	mem.type = MemoryType_EffectiveAddress;

	if (mod == 0b00)
	{
		if (rm == 0b110) {
			return memory_from_direct_address(w);
		}
		else {
			set_effective_address_registers(&mem, rm);
		}
	}
	else if (mod == 0b01)
	{
		set_effective_address_registers(&mem, rm);
		mem.address.displacement = (i32)(i8)program_read_byte();
	}
	else if (mod == 0b10) {
		set_effective_address_registers(&mem, rm);
		mem.address.displacement = (i32)(i16)program_read_word();
	}

	return mem;
}

InstructionMemory memory_from_immediate(b8 w)
{
	InstructionMemory mem{};
	mem.type = MemoryType_Immediate;
	mem.immediate.word = w;

	if (w) mem.immediate.value = (i32)(i16)program_read_word();
	else mem.immediate.value = (i32)(i8)program_read_byte();

	return mem;
}

ArithmeticType get_arithmetic_type(u8 op) {
	if (op == 0b000) return ArithmeticType_Add;
	if (op == 0b101) return ArithmeticType_Sub;
	if (op == 0b111) return ArithmeticType_Cmp;
	return ArithmeticType_None;
}

InstructionData cpu_read_instruction()
{
	const u8 mov_op_code = 0b100010;
	const u8 mov_immediate_r_op_code = 0b1011;
	const u8 mov_immediate_rm_op_code = 0b1100011;
	const u8 mov_memory_to_accumulator_op_code = 0b1010000;
	const u8 mov_accumulator_to_memory_op_code = 0b1010001;

	const u8 arithmetic_immediate_rm_op_code = 0b100000;
	const u8 arithmetic_op_code = 0b00;
	const u8 arithmetic_immediate_to_accumulator_op_code = 0b00;

	const u8 jump_header = 0b0111;
	const u8 jump_on_equal_op_code = 0b010;
	const u8 jump_on_less_op_code = 0b110;
	const u8 jump_on_less_or_equal_op_code = 0b111;
	const u8 jump_on_greater_op_code = 0b001;
	const u8 jump_on_greater_or_equal_op_code = 0b011;
	const u8 jump_on_parity_op_code = 0b101;
	const u8 jump_on_overflow_op_code = 0b000;
	const u8 jump_on_sign_op_code = 0b100;

	InstructionData inst{};

	u8 byte = program_read_byte();

	if ((byte >> 2) == mov_op_code)
	{
		b8 d = (byte >> 1) & 1;
		b8 w = byte & 1;

		byte = program_read_byte();

		u8 mod = (byte >> 6) & 0b11;
		u8 reg = (byte >> 3) & 0b111;
		u8 rm = byte & 0b111;

		inst.operation_type = OperationType_Mov;

		InstructionMemory mem0 = memory_from_register(reg, w);
		InstructionMemory mem1 = memory_from_rm_field(rm, mod, w);

		if (d) {
			inst.dst = mem0;
			inst.src = mem1;
		}
		else {
			inst.dst = mem1;
			inst.src = mem0;
		}
	}
	else if ((byte >> 4) == mov_immediate_r_op_code)
	{
		b8 w = (byte >> 3) & 1;
		u8 reg = byte & 0b111;

		inst.operation_type = OperationType_Mov;

		inst.dst = memory_from_register(reg, w);
		inst.src = memory_from_immediate(w);
	}
	else if ((byte >> 1) == mov_immediate_rm_op_code)
	{
		b8 w = byte & 1;

		byte = program_read_byte();
		u8 mod = (byte >> 6) & 0b11;
		u8 rm = byte & 0b111;

		inst.operation_type = OperationType_Mov;

		inst.dst = memory_from_rm_field(rm, mod, w);
		inst.src = memory_from_immediate(w);
	}

	else if ((byte >> 1) == mov_memory_to_accumulator_op_code)
	{
		b8 w = byte & 1;

		inst.operation_type = OperationType_Mov;

		inst.dst = memory_from_register(RegisterIndex_AX, 1);
		inst.src = memory_from_direct_address(w);
	}
	else if ((byte >> 1) == mov_accumulator_to_memory_op_code)
	{
		b8 w = byte & 1;

		inst.operation_type = OperationType_Mov;

		inst.src = memory_from_register(RegisterIndex_AX, 1);
		inst.dst = memory_from_direct_address(w);
	}

	else if (((byte >> 6) == arithmetic_op_code) && (((byte >> 2) & 0b1) == 0))
	{
		b8 d = (byte >> 1) & 1;
		b8 w = byte & 1;
		u8 op = (byte >> 3) & 0b111;

		byte = program_read_byte();

		u8 mod = (byte >> 6) & 0b11;
		u8 reg = (byte >> 3) & 0b111;
		u8 rm = byte & 0b111;

		inst.operation_type = OperationType_Arithmetic;
		inst.arithmetic_type = get_arithmetic_type(op);

		InstructionMemory mem0 = memory_from_register(reg, w);
		InstructionMemory mem1 = memory_from_rm_field(rm, mod, w);

		if (d) {
			inst.dst = mem0;
			inst.src = mem1;
		}
		else {
			inst.dst = mem1;
			inst.src = mem0;
		}
	}
	else if (((byte) >> 2) == arithmetic_immediate_rm_op_code)
	{
		b8 s = (byte >> 1) & 1; // Sign extension
		b8 w = byte & 1;

		byte = program_read_byte();

		u8 mod = (byte >> 6) & 0b11;
		u8 rm = byte & 0b111;
		u8 op = (byte >> 3) & 0b111;

		inst.operation_type = OperationType_Arithmetic;
		inst.arithmetic_type = get_arithmetic_type(op);

		inst.dst = memory_from_rm_field(rm, mod, w);
		if (s) inst.src = memory_from_immediate(0); // TODO: Is this right?
		else inst.src = memory_from_immediate(w);
	}
	else if (((byte >> 6) == arithmetic_immediate_to_accumulator_op_code) && (((byte >> 1) & 0b11) == 0b10)) {
		b8 w = byte & 1;
		u8 op = (byte >> 3) & 0b111;

		inst.operation_type = OperationType_Arithmetic;
		inst.arithmetic_type = get_arithmetic_type(op);
		
		inst.dst = w ? memory_from_register(RegisterIndex_AX, 1) : memory_from_register(RegisterIndex_AL, 0);
		inst.src = memory_from_immediate(w);
	}

	else if ((byte >> 4) == jump_header)
	{
		b8 negation = byte & 0b1;
		u8 jmp = (byte >> 1) & 0b111;

		JumpType t = JumpType_None;
		if (jmp == jump_on_equal_op_code) t = JumpType_Equals;
		else if (jmp == jump_on_less_op_code) t = JumpType_Lesser;
		else if (jmp == jump_on_less_or_equal_op_code) t = JumpType_LesserEquals;
		else if (jmp == jump_on_greater_op_code) t = JumpType_Greater;
		else if (jmp == jump_on_greater_or_equal_op_code) t = JumpType_GreaterEquals;
		else if (jmp == jump_on_parity_op_code) t = JumpType_Parity;
		else if (jmp == jump_on_overflow_op_code) t = JumpType_Overflow;
		else if (jmp == jump_on_sign_op_code) t = JumpType_Sign;
		
		inst.operation_type = OperationType_Jump;
		inst.jump.type = t;
		inst.jump.negation = negation;
		inst.jump.displacement = program_read_byte();
	}

	else {
		inst.operation_type = OperationType_Unknown;

		printf("Unknown OP: ");
		for (i32 i = 0; i < 8; ++i) printf("%s", ((byte >> i) & 1) ? "1" : "0");
		printf("\n");

		cpu_crash();
	}
	
	
	return inst;
}

#define print_inst(str, ...) do { if (cpu.debug.print_decoding) printf("    "); printf(str, __VA_ARGS__); printf("\n"); } while(0)

void print_flags() {
	b8 sign = (cpu.flags & (1 << RegisterFlag_SF)) != 0;
	b8 parity = (cpu.flags & (1 << RegisterFlag_PF)) != 0;
	b8 zero = (cpu.flags & (1 << RegisterFlag_ZF)) != 0;

	print_inst("Flags -> S%i, P%i, Z%i", (i32)sign, (i32)parity, (i32)zero);
}

void print_unknown_clocks() {
	printf("Unknown clock count\n");
}

u32 calculate_effective_address_clocks(InstructionMemory mem) {
	if (mem.type != MemoryType_EffectiveAddress) return 0;

	if (mem.address.reg_count == 0) return 6;
	if (mem.address.reg_count == 1 && mem.address.displacement == 0) return 5;
	if (mem.address.reg_count == 1 && mem.address.displacement != 0) return 9;

	if (mem.address.reg_count == 2 && mem.address.displacement == 0) {
		if (mem.address.reg0 == RegisterIndex_BP && mem.address.reg1 == RegisterIndex_SI) return 8;
		if (mem.address.reg0 == RegisterIndex_BX && mem.address.reg1 == RegisterIndex_DI) return 8;
		return 7;
	}

	if (mem.address.reg_count == 2 && mem.address.displacement != 0) {
		if (mem.address.reg0 == RegisterIndex_BP && mem.address.reg1 == RegisterIndex_SI) return 12;
		if (mem.address.reg0 == RegisterIndex_BX && mem.address.reg1 == RegisterIndex_DI) return 12;
		return 11;
	}

	print_unknown_clocks();
	return 0;
}

u16 get_register_value(u16 index, u8 w) {
	if (w) return cpu.reg.w[index];
	return (u16)cpu.reg.b[index];
}

i32 calculate_pointer(u8 reg0, u8 reg1, u8 reg_count, u16 displacement) {
	i32 ptr = displacement;
	if (reg_count >= 1) ptr += get_register_value(reg0, 1);
	if (reg_count >= 2) ptr += get_register_value(reg1, 1);
	return ptr;
}

u16 get_value(InstructionMemory mem)
{
	if (mem.type == MemoryType_Register) {
		return get_register_value(mem.reg.index, mem.reg.word);
	}
	else if (mem.type == MemoryType_Immediate) {
		return mem.immediate.value;
	}
	else {
		i32 ptr = calculate_pointer(mem.address.reg0, mem.address.reg1, mem.address.reg_count, mem.address.displacement);
		b8 word = 1; // TODO
		
		if (ptr <= 0) {
			printf("Invalid Pointer!!\n");
			cpu_crash();
		}

		if (word) return *((u16*)(cpu.memory + ptr));
		return (u16)cpu.memory[ptr];
	}
}

void set_value(InstructionMemory mem, u16 value)
{
	if (mem.type == MemoryType_Register) {
		if (mem.reg.word) cpu.reg.w[mem.reg.index] = value;
		else cpu.reg.b[mem.reg.index] = (u8)value;

		if (cpu.debug.print_instruction_info) {
			print_inst("Reg %s -> %i", get_register_name(mem.reg.index, mem.reg.word), (i32)value);
		}
	}
	else if (mem.type == MemoryType_Immediate) {
		printf("Can't modify immedate memory\n");
		cpu_crash();
	}
	else {
		i32 ptr = calculate_pointer(mem.address.reg0, mem.address.reg1, mem.address.reg_count, mem.address.displacement);
		b8 word = 1; // TODO

		if (ptr <= 0) {
			printf("Invalid Pointer!!\n");
			cpu_crash();
		}

		if (word) *((u16*)(cpu.memory + ptr)) = value;
		else cpu.memory[ptr] = (u8)value;

		if (cpu.debug.print_instruction_info) {
			print_inst("Write %s %i at %i", word ? "word" : "byte", (i32)value, ptr);
		}
	}
}

void set_flag(i16 index, b8 value) {
	if (value) cpu.flags |= (1 << index);
	else cpu.flags &= ~(1 << index);
}

b8 get_flag(i16 index) {
	return (cpu.flags & (1 << index)) != 0;
}

void set_flags_from_result(i16 result) {
	b8 sign = result < 0;
	b8 parity = !(result & 1);
	b8 zero = result == 0;

	set_flag(RegisterFlag_SF, sign);
	set_flag(RegisterFlag_PF, parity);
	set_flag(RegisterFlag_ZF, zero);

	if (cpu.debug.print_instruction_info) print_flags();
}

void set_ip(i16 value) {
	cpu.ip = value;
	if (cpu.debug.print_instruction_info) print_inst("IP: %i", (i32)value);
}

void cpu_execute_instruction(InstructionData inst)
{
	switch (inst.operation_type)
	{

	case OperationType_Mov:
	{
		i16 value = get_value(inst.src);
		set_value(inst.dst, value);

		cpu.clocks += calculate_effective_address_clocks(inst.dst);
		cpu.clocks += calculate_effective_address_clocks(inst.src);

		if (inst.dst.type == MemoryType_Register && inst.src.type == MemoryType_Register) cpu.clocks += 2;
		else if (inst.dst.type == MemoryType_Register && inst.src.type == MemoryType_EffectiveAddress) cpu.clocks += 8;
		else if (inst.dst.type == MemoryType_EffectiveAddress && inst.src.type == MemoryType_Register) cpu.clocks += 9;
		else if (inst.dst.type == MemoryType_Register && inst.src.type == MemoryType_Immediate) cpu.clocks += 4;
		else if (inst.dst.type == MemoryType_EffectiveAddress && inst.src.type == MemoryType_Immediate) cpu.clocks += 10;
		else print_unknown_clocks();
	} break;

	case OperationType_Arithmetic:
	{
		i16 src_value = get_value(inst.src);
		i16 dst_value = get_value(inst.dst);

		cpu.clocks += calculate_effective_address_clocks(inst.dst);
		cpu.clocks += calculate_effective_address_clocks(inst.src);

		if (inst.arithmetic_type == ArithmeticType_Add) {
			dst_value += src_value;
			set_value(inst.dst, dst_value);
			set_flags_from_result(dst_value);

			if (inst.dst.type == MemoryType_Register && inst.src.type == MemoryType_Register) cpu.clocks += 3;
			else if (inst.dst.type == MemoryType_Register && inst.src.type == MemoryType_EffectiveAddress) cpu.clocks += 9;
			else if (inst.dst.type == MemoryType_EffectiveAddress && inst.src.type == MemoryType_Register) cpu.clocks += 16;
			else if (inst.dst.type == MemoryType_Register && inst.src.type == MemoryType_Immediate) cpu.clocks += 4;
			else if (inst.dst.type == MemoryType_EffectiveAddress && inst.src.type == MemoryType_Immediate) cpu.clocks += 17;
			else print_unknown_clocks();
		}
		else if (inst.arithmetic_type == ArithmeticType_Sub) {
			dst_value -= src_value;
			set_value(inst.dst, dst_value);
			set_flags_from_result(dst_value);
		}
		else if (inst.arithmetic_type == ArithmeticType_Cmp) {
			dst_value -= src_value;
			set_flags_from_result(dst_value);
		}
	} break;

	case OperationType_Jump:
	{
		b8 res = 0;
		if (inst.jump.type == JumpType_Equals) res = get_flag(RegisterFlag_ZF);
		else if (inst.jump.type == JumpType_Lesser) res = !get_flag(RegisterFlag_SF) && !get_flag(RegisterFlag_ZF);
		else if (inst.jump.type == JumpType_LesserEquals) res = !get_flag(RegisterFlag_SF) || get_flag(RegisterFlag_ZF);
		else if (inst.jump.type == JumpType_Greater) res = get_flag(RegisterFlag_SF) && !get_flag(RegisterFlag_ZF);
		else if (inst.jump.type == JumpType_GreaterEquals) res = get_flag(RegisterFlag_SF) || get_flag(RegisterFlag_ZF);
		else if (inst.jump.type == JumpType_Sign) res = get_flag(RegisterFlag_SF);
		else { printf("TODO: Jump OP\n"); }

		if (inst.jump.negation) res = !res;

		if (res) set_ip(cpu.ip + (i16)(i8)inst.jump.displacement);
	} break;

	case OperationType_Unknown:
	case OperationType_None:
	default:
	{
		print_inst("*Invalid instruction to execute");
		// cpu_crash();
	} break;

	}
}

std::string read_immediate_data(b8 w, b8 explicit_sizes) {
	i32 data = 0;

	if (w) {
		i16 v = program_read_word();
		data = (i32)v;
	}
	else {
		i8 lb = program_read_byte();
		data = (i32)lb;
	}

	if (explicit_sizes) return std::string(w ? "word " : "byte ") + std::to_string(data);
	return std::to_string(data);
}

int main()
{
	cpu_initialize();

	const char* path;
	// path = "assets/listing_0037_single_register_mov";
	// path = "assets/listing_0038_many_register_mov";
	// path = "assets/listing_0039_more_movs";
	// path = "assets/listing_0040_challenge_movs";
	// path = "assets/listing_0041_add_sub_cmp_jnz";
	// path = "assets/listing_0043_immediate_movs";
	// path = "assets/listing_0044_register_movs";
	// path = "assets/listing_0045_challenge_register_movs";
	// path = "assets/listing_0046_add_sub_cmp";
	// path = "assets/listing_0049_conditional_jumps";
	// path = "assets/listing_0051_memory_mov";
	// path = "assets/listing_0052_memory_add_loop";
	// path = "assets/listing_0053_add_loop_challenge";
	path = "assets/listing_0056_estimating_cycles";
	// path = "assets/listing_0057_challenge_cycles";

	if (!cpu_load_program(path)) return -1;

	cpu.debug.print_decoding = 1;
	cpu.debug.print_instruction_info = 0;
	cpu.debug.print_clocks = 1;

	while (!program_finished())
	{
		InstructionData inst = cpu_read_instruction();
		if (cpu.debug.print_decoding) print_decoding(inst);
		
		u32 last_clocks = cpu.clocks;
		cpu_execute_instruction(inst);

		if (cpu.debug.print_clocks) print_inst("Clocks %i -> %i; %i", last_clocks, cpu.clocks, cpu.clocks - last_clocks);
	}

	printf("\nResult:\n");
	printf("\tClocks: %i\n", cpu.clocks);

	return 0;
}