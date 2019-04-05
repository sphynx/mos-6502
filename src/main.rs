const MEM_SIZE: usize = 64 * 1024;

use Op::*;
use AddrMode::*;

#[allow(dead_code)]
pub struct CPU {
    /// 64k of addressable memory. First page, i.e. first 256 bytes
    /// ($0000 - $00FF) is called 'Zero Page' and is used in address
    /// modes. The second page is used as the system stack. Last 6
    /// bytes are reserved for addresses of non-masked interrupts
    /// handler, power on reset location and BRK/interrupt request
    /// handler.
    pub mem: [u8; MEM_SIZE],

    /// Instruction pointer (aka Program counter). Points to the
    /// *next* instruction to be executed.
    pub ip: u16,

    /// Stack pointer. Points to the next free location on the stack.
    /// Stack grows down, i.e. pushing decrements `sp`.
    pub sp: u8,

    /// Accumulator register (aka "A" register).
    pub reg_acc: u8,

    /// X register.
    pub reg_x: u8,

    /// Y register.
    pub reg_y: u8,

    /// Status register (aka "P" or flags register). Bits description:
    ///
    /// ```
    /// 76543210
    /// NV-BDIZC
    /// ```
    ///
    /// - N - negative result.
    /// - V - overflow.
    /// - B - break command.
    /// - D - decimal mode.
    /// - I - interrupt disable.
    /// - Z - zero result.
    /// - C - carry.
    pub reg_status: u8,
}

#[allow(dead_code)]
struct Instr(Op, AddrMode);

#[allow(dead_code)]
enum Op {
    ADC,
    AND,
    ASL,
    BCC,
    BCS,
    BEQ,
    BIT,
    BMI,
    BNE,
    BPL,
    BRK,
    BVC,
    BVS,
    CLC,
    CLD,
    CLI,
    CLV,
    CMP,
    CPX,
    CPY,
    DEC,
    DEX,
    DEY,
    EOR,
    INC,
    INX,
    INY,
    JMP,
    JSR,
    LDA,
    LDX,
    LDY,
    LSR,
    NOP,
    ORA,
    PHA,
    PHP,
    PLA,
    PLP,
    ROL,
    ROR,
    RTI,
    RTS,
    SBC,
    SEC,
    SED,
    SEI,
    STA,
    STX,
    STY,
    TAX,
    TAY,
    TSX,
    TXA,
    TXS,
    TYA,
}

#[allow(dead_code)]
enum AddrMode {
    Impl,
    Abs,
    AbsX,
    AbsY,
    Imm,
    Ind,
    IndX,
    IndY,
    Rel,
    Zpg,
    ZpgX,
    ZpgY,
}

impl Instr {
    #[allow(dead_code)]
    pub fn decode(op_code: u8) -> Self {
        match op_code {
            0x00 => Instr(BRK, Impl),
            0x01 => Instr(ORA, IndX),
            0x05 => Instr(ORA, Zpg),
            0x06 => Instr(ASL, Zpg),
            0x08 => Instr(PHP, Impl),
            0x09 => Instr(ORA, Imm),
            0x0A => Instr(ASL, Impl),
            0x0D => Instr(ORA, Abs),
            0x0E => Instr(ASL, Abs),

            0x10 => Instr(BPL, Rel),
            0x11 => Instr(ORA, IndY),
            0x15 => Instr(ORA, ZpgX),
            0x16 => Instr(ASL, ZpgX),
            0x18 => Instr(CLC, Impl),
            0x19 => Instr(ORA, AbsY),
            0x1D => Instr(ORA, AbsX),
            0x1E => Instr(ASL, AbsX),

            0x20 => Instr(JSR, Abs),
            0x21 => Instr(AND, IndX),
            0x24 => Instr(BIT, Zpg),
            0x25 => Instr(AND, Zpg),
            0x26 => Instr(ROL, Zpg),
            0x28 => Instr(PLP, Impl),
            0x29 => Instr(AND, Imm),
            0x2A => Instr(ROL, Impl),
            0x2C => Instr(BIT, Abs),
            0x2D => Instr(AND, Abs),
            0x2E => Instr(ROL, Abs),

            0x30 => Instr(BMI, Rel),
            0x31 => Instr(AND, IndY),
            0x35 => Instr(AND, ZpgX),
            0x36 => Instr(ROL, ZpgX),
            0x38 => Instr(SEC, Impl),
            0x39 => Instr(AND, AbsY),
            0x3D => Instr(AND, AbsX),
            0x3E => Instr(ROL, AbsX),

            0x40 => Instr(RTI, Impl),
            0x41 => Instr(EOR, IndX),
            0x45 => Instr(EOR, Zpg),
            0x46 => Instr(LSR, Zpg),
            0x48 => Instr(PHA, Impl),
            0x49 => Instr(EOR, Imm),
            0x4A => Instr(LSR, Impl),
            0x4C => Instr(JMP, Abs),
            0x4D => Instr(EOR, Abs),
            0x4E => Instr(LSR, Abs),

            0x50 => Instr(BVC, Rel),
            0x51 => Instr(EOR, IndY),
            0x55 => Instr(EOR, ZpgX),
            0x56 => Instr(LSR, ZpgX),
            0x58 => Instr(CLI, Impl),
            0x59 => Instr(EOR, AbsY),
            0x5D => Instr(EOR, AbsX),
            0x5E => Instr(LSR, AbsX),

            0x60 => Instr(RTS, Impl),
            0x61 => Instr(ADC, IndX),
            0x65 => Instr(ADC, Zpg),
            0x66 => Instr(ROR, Zpg),
            0x68 => Instr(PLA, Impl),
            0x69 => Instr(ADC, Imm),
            0x6A => Instr(ROR, Impl),
            0x6C => Instr(JMP, Ind),
            0x6D => Instr(ADC, Abs),
            0x6E => Instr(ROR, Abs),

            0x70 => Instr(BVS, Rel),
            0x71 => Instr(ADC, IndY),
            0x75 => Instr(ADC, ZpgX),
            0x76 => Instr(ROR, ZpgX),
            0x78 => Instr(SEI, Impl),
            0x79 => Instr(ADC, AbsY),
            0x7D => Instr(ADC, AbsX),
            0x7E => Instr(ROR, AbsX),

            0x81 => Instr(STA, IndX),
            0x84 => Instr(STY, Zpg),
            0x85 => Instr(STA, Zpg),
            0x86 => Instr(STX, Zpg),
            0x88 => Instr(DEY, Impl),
            0x8A => Instr(TXA, Impl),
            0x8C => Instr(STY, Abs),
            0x8D => Instr(STA, Abs),
            0x8E => Instr(STX, Abs),

            0x90 => Instr(BCC, Rel),
            0x91 => Instr(STA, IndY),
            0x94 => Instr(STY, ZpgX),
            0x95 => Instr(STA, ZpgX),
            0x96 => Instr(STX, ZpgY),
            0x98 => Instr(TYA, Impl),
            0x99 => Instr(STA, AbsY),
            0x9A => Instr(TXS, Impl),
            0x9D => Instr(STA, AbsX),

            0xA0 => Instr(LDY, Imm),
            0xA1 => Instr(LDA, IndX),
            0xA2 => Instr(LDX, Imm),
            0xA4 => Instr(LDY, Zpg),
            0xA5 => Instr(LDA, Zpg),
            0xA6 => Instr(LDX, Zpg),
            0xA8 => Instr(TAY, Impl),
            0xA9 => Instr(LDA, Imm),
            0xAA => Instr(TAX, Impl),
            0xAC => Instr(LDY, Abs),
            0xAD => Instr(LDA, Abs),
            0xAE => Instr(LDX, Abs),

            0xB0 => Instr(BCS, Rel),
            0xB1 => Instr(LDA, IndY),
            0xB4 => Instr(LDY, ZpgX),
            0xB5 => Instr(LDA, ZpgX),
            0xB6 => Instr(LDX, ZpgY),
            0xB8 => Instr(CLV, Impl),
            0xB9 => Instr(LDA, AbsY),
            0xBA => Instr(TSX, Impl),
            0xBC => Instr(LDY, AbsX),
            0xBD => Instr(LDA, AbsX),
            0xBE => Instr(LDX, AbsY),

            0xC0 => Instr(CPY, Imm),
            0xC1 => Instr(CMP, IndX),
            0xC4 => Instr(CPY, Zpg),
            0xC5 => Instr(CMP, Zpg),
            0xC6 => Instr(DEC, Zpg),
            0xC8 => Instr(INY, Impl),
            0xC9 => Instr(CMP, Imm),
            0xCA => Instr(DEX, Impl),
            0xCC => Instr(CPY, Abs),
            0xCD => Instr(CMP, Abs),
            0xCE => Instr(DEC, Abs),

            0xD0 => Instr(BNE, Rel),
            0xD1 => Instr(CMP, IndY),
            0xD5 => Instr(CMP, ZpgX),
            0xD6 => Instr(DEC, ZpgX),
            0xD8 => Instr(CLD, Impl),
            0xD9 => Instr(CMP, AbsY),
            0xDD => Instr(CMP, AbsX),
            0xDE => Instr(DEC, AbsX),

            0xE0 => Instr(CPX, Imm),
            0xE1 => Instr(SBC, IndX),
            0xE4 => Instr(CPX, Zpg),
            0xE5 => Instr(SBC, Zpg),
            0xE6 => Instr(INC, Zpg),
            0xE8 => Instr(INX, Impl),
            0xE9 => Instr(SBC, Imm),
            0xEA => Instr(NOP, Impl),
            0xEC => Instr(CPX, Abs),
            0xED => Instr(SBC, Abs),
            0xEE => Instr(INC, Abs),

            0xF0 => Instr(BEQ, Rel),
            0xF1 => Instr(SBC, IndY),
            0xF5 => Instr(SBC, ZpgX),
            0xF6 => Instr(INC, ZpgX),
            0xF8 => Instr(SED, Impl),
            0xF9 => Instr(SBC, AbsY),
            0xFD => Instr(SBC, AbsX),
            0xFE => Instr(INC, AbsX),

            _ => panic!("unknown op code: {}", op_code)

        }
    }
}

impl CPU {
    pub fn load(&mut self, prog: &[u8]) {
        // FIXME: where the programs are usually loaded?
        // For now let's load it at 0.
        let addr = 0;
        let len = prog.len();
        assert!(addr + len < MEM_SIZE);
        self.mem[addr..addr + len].copy_from_slice(prog);
    }

    pub fn run(&mut self) {
        // let op = decode();
        //execute(op);
    }
}

fn main() {
    println!("Hello, world!");
}
