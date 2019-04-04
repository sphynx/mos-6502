const MEM_SIZE: usize = 64 * 1024;

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

impl Op {
    #[allow(dead_code)]
    pub fn decode() -> Self {
        // FIXME
        Op::TAX
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
