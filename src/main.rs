const MEM_SIZE: usize = 64 * 1024;

use std::env;
use std::fs;
use std::process;

use AddrMode::*;
use Op::*;
use Operand::*;

pub struct Mem {
    data: [u8; MEM_SIZE],
}

pub struct CPU {
    /// 64k of addressable memory. First page, i.e. first 256 bytes
    /// ($0000 - $00FF) is called 'Zero Page' and is used in address
    /// modes. The second page is used as the system stack. Last 6
    /// bytes are reserved for addresses of non-masked interrupts
    /// handler, power on reset location and BRK/interrupt request
    /// handler.
    pub mem: Mem,

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

#[derive(Debug)]
pub struct Instr(Op, AddrMode);

#[derive(Debug)]
pub enum Op {
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

#[derive(Debug)]
pub enum AddrMode {
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

#[derive(Debug)]
pub enum Operand {
    Address(u16),
    // special treatment for Ind mode only used in Jmp
    JmpAddress(u16),
    Byte(u8),
    Offset(i8),
    Implicit,
}

impl Instr {
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

            _ => panic!("unknown op code: {}", op_code),
        }
    }
}

pub fn offset(mode: &AddrMode) -> u16 {
    match mode {
        Impl => 0,
        Abs => 2,
        AbsX => 2,
        AbsY => 2,
        Imm => 1,
        Ind => 2,
        IndX => 1,
        IndY => 1,
        Rel => 1,
        Zpg => 1,
        ZpgX => 1,
        ZpgY => 1,
    }
}

pub fn disasm(bytes: &[u8]) {
    let mut ip = 0;
    let len = bytes.len();
    while ip < len {
        let op_code = bytes[ip];
        ip += 1;
        let instr = Instr::decode(op_code);
        println!("{:?}", instr);
        ip += offset(&instr.1) as usize;
    }
}

impl CPU {
    pub fn new() -> Self {
        CPU {
            ip: 0x0000_u16,
            sp: 0xFF,
            reg_acc: 0x00,
            reg_x: 0x00,
            reg_y: 0x00,
            reg_status: 0b_0000_0000,
            mem: Mem {
                data: [0; MEM_SIZE],
            },
        }
    }

    pub fn load(&mut self, addr: usize, prog: &[u8]) {
        let len = prog.len();
        assert!(addr + len < MEM_SIZE);
        self.mem.data[addr..addr + len].copy_from_slice(prog);
    }

    pub fn run(&mut self) {
        // FIXME: when to stop? :)
        loop {
            // fetch next instruction
            let op_code = self.mem.data[self.ip as usize];
            self.ip = self.ip.wrapping_add(1);

            // decode
            let instr = Instr::decode(op_code);
            let operand = self.resolve_operand(&instr.1);
            self.ip = self.ip.wrapping_add(offset(&instr.1));

            // execute
            self.execute(instr.0, operand);
        }
    }

    pub fn dump(&self) -> String {
        // Something like: "A:00 X:00 Y:00 P:24 SP:FD IP:C000"
        format!(
            "A:{:02X} X:{:02X} Y:{:02X} P:{:02X} SP:{:02X} IP:{:04X}",
            self.reg_acc, self.reg_x, self.reg_y, self.reg_status, self.sp, self.ip
        )
    }

    fn execute(&mut self, op: Op, operand: Operand) {
        match op {
            LDA => {
                match operand {
                    Address(addr) => self.reg_acc = self.mem.data[addr as usize],
                    Byte(val) => self.reg_acc = val,
                    o => panic!("execute: LDA: wrong operand: {:?}", o),
                }
                self.update_zero_flag(self.reg_acc == 0);
                self.update_negative_flag(self.reg_acc);
            }

            STA => match operand {
                Address(addr) => self.mem.data[addr as usize] = self.reg_acc,
                o => panic!("execute: STA: wrong operand: {:?}", o),
            },

            ADC => {
                let m = match operand {
                    Byte(val) => val,
                    Address(addr) => self.mem.data[addr as usize],
                    o => panic!("execute: ADC: wrong operand: {:?}", o),
                };
                self.adc(m);
            }

            SBC => {
                let m = match operand {
                    Byte(val) => val,
                    Address(addr) => self.mem.data[addr as usize],
                    o => panic!("execute: SBC: wrong operand: {:?}", o),
                };

                if self.get_decimal_flag() {
                    let bcd_a = BCD::new(self.reg_acc);
                    let bcd_x = BCD::new(m);
                    // TODO: should we actually handle carry flag in this way?
                    let c = if self.get_carry_flag() { 0 } else { 1 };
                    let bcd_diff = bcd_a.to_decimal() - bcd_x.to_decimal() + c;
                    let carry = (bcd_diff as i8) < 0;
                    let result_dec = bcd_diff % 100;
                    let res = BCD::from_decimal(result_dec).bits;
                    self.reg_acc = res;

                    // We don't update overflow and negative flags,
                    // since it's not properly documented whether how
                    // they should be updated.

                    self.update_carry_flag(carry);
                    self.update_zero_flag(self.reg_acc == 0);
                } else {
                    self.adc(!m);
                }
            }

            AND => {
                let m = match operand {
                    Byte(val) => val,
                    Address(addr) => self.mem.data[addr as usize],
                    o => panic!("execute: AND: wrong operand: {:?}", o),
                };
                self.reg_acc = self.reg_acc & m;
                self.update_zero_flag(self.reg_acc == 0);
                self.update_negative_flag(self.reg_acc);
            }

            ORA => {
                let m = match operand {
                    Byte(val) => val,
                    Address(addr) => self.mem.data[addr as usize],
                    o => panic!("execute: AND: wrong operand: {:?}", o),
                };
                self.reg_acc = self.reg_acc | m;
                self.update_zero_flag(self.reg_acc == 0);
                self.update_negative_flag(self.reg_acc);
            }

            EOR => {
                let m = match operand {
                    Byte(val) => val,
                    Address(addr) => self.mem.data[addr as usize],
                    o => panic!("execute: AND: wrong operand: {:?}", o),
                };
                self.reg_acc = self.reg_acc ^ m;
                self.update_zero_flag(self.reg_acc == 0);
                self.update_negative_flag(self.reg_acc);
            }

            SEC => self.set_carry_flag(),
            CLC => self.clear_carry_flag(),

            SEI => self.set_interrupt_flag(),
            CLI => self.clear_interrupt_flag(),

            SED => self.set_decimal_flag(),
            CLD => self.clear_decimal_flag(),

            CLV => self.clear_overflow_flag(),

            JMP => {
                let addr = match operand {
                    Address(addr) => addr,
                    JmpAddress(addr) => addr,
                    o => panic!("execute: JMP: wrong operand: {:?}", o),
                };
                self.ip = addr;
            }

            BMI => {
                if let Offset(off) = operand {
                    if self.get_negative_flag() {
                        self.ip = self.ip.wrapping_add(off as u16);
                    }
                }
            }

            BPL => {
                if let Offset(off) = operand {
                    if !self.get_negative_flag() {
                        self.ip = self.ip.wrapping_add(off as u16);
                    }
                }
            }

            BCS => {
                if let Offset(off) = operand {
                    if self.get_carry_flag() {
                        self.ip = self.ip.wrapping_add(off as u16);
                    }
                }
            }

            BCC => {
                if let Offset(off) = operand {
                    if !self.get_carry_flag() {
                        self.ip = self.ip.wrapping_add(off as u16);
                    }
                }
            }

            BEQ => {
                if let Offset(off) = operand {
                    if self.get_zero_flag() {
                        self.ip = self.ip.wrapping_add(off as u16);
                    }
                }
            }

            BNE => {
                if let Offset(off) = operand {
                    if !self.get_zero_flag() {
                        self.ip = self.ip.wrapping_add(off as u16);
                    }
                }
            }

            BVS => {
                if let Offset(off) = operand {
                    if self.get_overflow_flag() {
                        self.ip = self.ip.wrapping_add(off as u16);
                    }
                }
            }

            BVC => {
                if let Offset(off) = operand {
                    if !self.get_overflow_flag() {
                        self.ip = self.ip.wrapping_add(off as u16);
                    }
                }
            }

            CMP | CPX | CPY => {
                let reg = match op {
                    CMP => self.reg_acc,
                    CPX => self.reg_x,
                    CPY => self.reg_y,
                    _ => panic!("execute: CMP: shouldn't happen"),
                };
                let m = match operand {
                    Byte(val) => val,
                    Address(addr) => self.mem.data[addr as usize],
                    o => panic!("execute: {:?}: wrong operand: {:?}", op, o),
                };
                let res = reg.wrapping_sub(m);
                self.update_zero_flag(res == 0);
                self.update_negative_flag(res);
                self.update_carry_flag(reg >= m);
            }

            BIT => {
                let m = match operand {
                    Address(addr) => self.mem.data[addr as usize],
                    _ => panic!("execute: {:?}: wrong operand: {:?}", op, operand),
                };
                let a = self.reg_acc;
                self.update_zero_flag(a & m == 0);
                self.update_negative_flag(m);
                self.update_overflow_flag(get_bit(m, 6));
            }

            _ => unimplemented!(),
        }
    }

    fn adc(&mut self, x: u8) {
        if self.get_decimal_flag() {
            let bcd_a = BCD::new(self.reg_acc);
            let bcd_x = BCD::new(x);
            let c = if self.get_carry_flag() { 1 } else { 0 };
            let bcd_sum = bcd_a.to_decimal() + bcd_x.to_decimal() + c;
            let carry = bcd_sum > 99;
            let result_dec = bcd_sum % 100;
            let res = BCD::from_decimal(result_dec).bits;
            self.reg_acc = res;

            // We don't update overflow and negative flags,
            // since it's not properly documented whether how
            // they should be updated.

            self.update_carry_flag(carry);
            self.update_zero_flag(self.reg_acc == 0);
        } else {
            let a = self.reg_acc;
            let c: u16 = if self.get_carry_flag() { 1 } else { 0 };

            let u_res: u16 = (x as u16).wrapping_add(a as u16).wrapping_add(c);
            let signed_res: i16 = ((x as i8) as i16)
                .wrapping_add((a as i8) as i16)
                .wrapping_add(c as i16);

            let carry = u_res > std::u8::MAX as u16;
            let overflow = signed_res > std::i8::MAX as i16 || signed_res < std::i8::MIN as i16;

            self.reg_acc = (u_res & 0xFF) as u8;
            self.update_carry_flag(carry);
            self.update_overflow_flag(overflow);
            self.update_zero_flag(self.reg_acc == 0);
            self.update_negative_flag(self.reg_acc);
        }
    }

    fn resolve_operand(&self, mode: &AddrMode) -> Operand {
        match mode {
            Impl => Implicit,
            Abs => {
                let lo = self.mem.data[self.ip as usize];
                let hi = self.mem.data[(self.ip.wrapping_add(1)) as usize];
                let addr = ((hi as u16) << 8) | (lo as u16);
                Address(addr)
            }
            AbsX => {
                let lo = self.mem.data[self.ip as usize];
                let hi = self.mem.data[(self.ip.wrapping_add(1)) as usize];
                let addr = ((hi as u16) << 8) | (lo as u16);
                Address(addr.wrapping_add(self.reg_x as u16))
            }
            AbsY => {
                let lo = self.mem.data[self.ip as usize];
                let hi = self.mem.data[(self.ip.wrapping_add(1)) as usize];
                let addr = ((hi as u16) << 8) | (lo as u16);
                Address(addr.wrapping_add(self.reg_y as u16))
            }
            Imm => Byte(self.mem.data[self.ip as usize]),
            Ind => {
                // This addressing mode is only used for JMP. And it
                // is buggy: an original 6502 does not correctly fetch
                // the target address if the indirect vector falls on
                // a page boundary (e.g. $xxFF where xx is any value
                // from $00 to $FF). In this case it fetches the LSB
                // from $xxFF as expected but takes the MSB from
                // $xx00.

                let indir_lo = self.mem.data[self.ip as usize];
                let indir_hi = self.mem.data[(self.ip.wrapping_add(1)) as usize];
                let indir_addr = ((indir_hi as u16) << 8) | (indir_lo as u16);
                let lo = self.mem.data[indir_addr as usize];

                // I support that buggy behaviour here:
                let hi = if indir_lo != 0xFF {
                    self.mem.data[indir_addr.wrapping_add(1) as usize]
                } else {
                    let buggy_hi_addr = (indir_hi as u16) << 8;
                    self.mem.data[buggy_hi_addr as usize]
                };
                let addr = ((hi as u16) << 8) | (lo as u16);
                JmpAddress(addr)
            }
            IndX => {
                let indir_lo = self.mem.data[self.ip as usize];
                let indir_addr = indir_lo.wrapping_add(self.reg_x);
                let lo = self.mem.data[indir_addr as usize];
                let hi = self.mem.data[indir_addr.wrapping_add(1) as usize];
                let addr = ((hi as u16) << 8) | (lo as u16);
                Address(addr)
            }
            IndY => {
                let indir_addr = self.mem.data[self.ip as usize];
                let lo = self.mem.data[indir_addr as usize];
                let hi = self.mem.data[indir_addr.wrapping_add(1) as usize];
                let addr = ((hi as u16) << 8) | (lo as u16);
                Address(addr.wrapping_add(self.reg_y as u16))
            }
            Rel => Offset(self.mem.data[self.ip as usize] as i8),
            Zpg => Address(self.mem.data[self.ip as usize] as u16),
            ZpgX => {
                let addr = self.mem.data[self.ip as usize].wrapping_add(self.reg_x);
                Address(addr as u16)
            }
            ZpgY => {
                let addr = self.mem.data[self.ip as usize].wrapping_add(self.reg_y);
                Address(addr as u16)
            }
        }
    }

    fn set_negative_flag(&mut self) {
        set_bit(&mut self.reg_status, 7);
    }

    fn get_negative_flag(&self) -> bool {
        get_bit(self.reg_status, 7)
    }

    fn clear_negative_flag(&mut self) {
        clear_bit(&mut self.reg_status, 7)
    }

    fn set_overflow_flag(&mut self) {
        set_bit(&mut self.reg_status, 6);
    }

    fn get_overflow_flag(&self) -> bool {
        get_bit(self.reg_status, 6)
    }

    fn clear_overflow_flag(&mut self) {
        clear_bit(&mut self.reg_status, 6)
    }

    #[allow(unused)]
    fn set_break_flag(&mut self) {
        set_bit(&mut self.reg_status, 4);
    }

    #[allow(unused)]
    fn get_break_flag(&self) -> bool {
        get_bit(self.reg_status, 4)
    }

    #[allow(unused)]
    fn clear_break_flag(&mut self) {
        clear_bit(&mut self.reg_status, 4)
    }

    fn set_decimal_flag(&mut self) {
        set_bit(&mut self.reg_status, 3);
    }

    fn get_decimal_flag(&self) -> bool {
        get_bit(self.reg_status, 3)
    }

    fn clear_decimal_flag(&mut self) {
        clear_bit(&mut self.reg_status, 3)
    }

    fn set_interrupt_flag(&mut self) {
        set_bit(&mut self.reg_status, 2);
    }

    #[allow(unused)]
    fn get_interrupt_flag(&self) -> bool {
        get_bit(self.reg_status, 2)
    }

    fn clear_interrupt_flag(&mut self) {
        clear_bit(&mut self.reg_status, 2)
    }

    fn set_zero_flag(&mut self) {
        set_bit(&mut self.reg_status, 1);
    }

    fn get_zero_flag(&self) -> bool {
        get_bit(self.reg_status, 1)
    }

    fn clear_zero_flag(&mut self) {
        clear_bit(&mut self.reg_status, 1);
    }

    fn set_carry_flag(&mut self) {
        set_bit(&mut self.reg_status, 0);
    }

    fn get_carry_flag(&self) -> bool {
        get_bit(self.reg_status, 0)
    }

    fn clear_carry_flag(&mut self) {
        clear_bit(&mut self.reg_status, 0)
    }

    fn update_zero_flag(&mut self, zero: bool) {
        if zero {
            self.set_zero_flag();
        } else {
            self.clear_zero_flag();
        }
    }

    fn update_negative_flag(&mut self, val: u8) {
        if val >= 0b_1000_0000 {
            self.set_negative_flag();
        } else {
            self.clear_negative_flag();
        }
    }

    fn update_carry_flag(&mut self, carry: bool) {
        if carry {
            self.set_carry_flag();
        } else {
            self.clear_carry_flag();
        }
    }

    fn update_overflow_flag(&mut self, overflow: bool) {
        if overflow {
            self.set_overflow_flag();
        } else {
            self.clear_overflow_flag();
        }
    }
}

fn set_bit(val: &mut u8, bit: usize) {
    *val |= 1_u8 << bit;
}

fn clear_bit(val: &mut u8, bit: usize) {
    *val &= !(1_u8 << bit);
}

fn get_bit(val: u8, bit: usize) -> bool {
    ((val >> bit) & 1_u8) != 0
}

#[allow(dead_code)]
fn toggle_bit(val: &mut u8, bit: usize) {
    *val ^= 1_u8 << bit;
}

pub struct BCD {
    pub bits: u8,
}

impl BCD {
    pub fn new(bits: u8) -> Self {
        BCD { bits }
    }

    pub fn to_decimal(&self) -> u8 {
        let hi = self.bits >> 4;
        let lo = self.bits & 0b_0000_1111;
        assert!(hi <= 9);
        assert!(lo <= 9);
        10 * hi + lo
    }

    pub fn from_decimal(dec: u8) -> Self {
        assert!(dec <= 99);
        let hi_digit: u8 = dec / 10;
        let lo_digit: u8 = dec % 10;
        BCD {
            bits: (hi_digit << 4) | lo_digit,
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        println!("usage: {} <program_file>", &args[0]);
        process::exit(1);
    }

    let file = &args[1];
    let bytes: Vec<u8> = fs::read(file).unwrap();
    disasm(&bytes);

    let mut cpu = CPU::new();
    cpu.load(0, &bytes);
    cpu.run();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_adc(a: u8, m: u8, c: bool) -> CPU {
        let mut cpu = CPU::new();
        cpu.reg_acc = a;
        if c {
            cpu.set_carry_flag();
        }
        cpu.execute(ADC, Byte(m));
        cpu
    }

    fn test_dec_adc(a: u8, m: u8, c: bool) -> CPU {
        let mut cpu = CPU::new();
        cpu.set_decimal_flag();
        cpu.reg_acc = a;
        if c {
            cpu.set_carry_flag();
        }
        cpu.execute(ADC, Byte(m));
        cpu
    }

    fn test_sbc(a: u8, m: u8, c: bool) -> CPU {
        let mut cpu = CPU::new();
        cpu.reg_acc = a;
        if c {
            cpu.set_carry_flag();
        }
        cpu.execute(SBC, Byte(m));
        cpu
    }

    fn test_dec_sbc(a: u8, m: u8, c: bool) -> CPU {
        let mut cpu = CPU::new();
        cpu.set_decimal_flag();
        cpu.reg_acc = a;
        if c {
            cpu.set_carry_flag();
        }
        cpu.execute(SBC, Byte(m));
        cpu
    }

    fn test_and(a: u8, m: u8) -> CPU {
        test_bin_op(AND, a, m)
    }

    fn test_ora(a: u8, m: u8) -> CPU {
        test_bin_op(ORA, a, m)
    }

    fn test_eor(a: u8, m: u8) -> CPU {
        test_bin_op(EOR, a, m)
    }

    fn test_cmp(a: u8, m: u8) -> CPU {
        test_bin_op(CMP, a, m)
    }

    fn test_bit(a: u8, m: u8) -> CPU {
        let mut cpu = CPU::new();
        cpu.reg_acc = a;
        cpu.mem.data[0] = m;
        cpu.execute(BIT, Address(0));
        cpu
    }

    fn test_bin_op(op: Op, a: u8, m: u8) -> CPU {
        let mut cpu = CPU::new();
        cpu.reg_acc = a;
        cpu.execute(op, Byte(m));
        cpu
    }

    #[test]
    fn adc_1() {
        let c = test_adc(1, 1, true);
        assert_eq!(c.dump(), "A:03 X:00 Y:00 P:00 SP:FF IP:0000");
        assert_eq!(c.reg_acc, 3);
    }

    #[test]
    fn adc_2() {
        let c = test_adc(13, 211, true);
        assert_eq!(c.reg_acc, 225);
        assert_eq!(c.get_carry_flag(), false);
    }

    #[test]
    fn adc_3() {
        let c = test_adc(254, 6, true);
        assert_eq!(c.reg_acc, 5);
        assert_eq!(c.get_carry_flag(), true);
        assert_eq!(c.get_negative_flag(), false);
    }

    #[test]
    fn adc_4() {
        let c = test_adc(5, 7, false);
        assert_eq!(c.reg_acc, 12);
        assert_eq!(c.get_carry_flag(), false);
        assert_eq!(c.get_overflow_flag(), false);
        assert_eq!(c.get_negative_flag(), false);
    }

    #[test]
    fn adc_5() {
        let c = test_adc(127, 2, false);
        assert_eq!(c.reg_acc, -127_i8 as u8);
        assert_eq!(c.get_carry_flag(), false);
        assert_eq!(c.get_overflow_flag(), true);
        assert_eq!(c.get_negative_flag(), true);
    }

    #[test]
    fn adc_6() {
        let c = test_adc(5, -3_i8 as u8, false);
        assert_eq!(c.reg_acc, 2);
        assert_eq!(c.get_carry_flag(), true);
        assert_eq!(c.get_overflow_flag(), false);
        assert_eq!(c.get_negative_flag(), false);
    }

    #[test]
    fn adc_7() {
        let c = test_adc(5, -7_i8 as u8, false);
        assert_eq!(c.reg_acc, -2_i8 as u8);
        assert_eq!(c.get_carry_flag(), false);
        assert_eq!(c.get_overflow_flag(), false);
        assert_eq!(c.get_negative_flag(), true);
    }

    #[test]
    fn adc_8() {
        let c = test_adc(-5_i8 as u8, -7_i8 as u8, false);
        assert_eq!(c.reg_acc, -12_i8 as u8);
        assert_eq!(c.get_carry_flag(), true);
        assert_eq!(c.get_overflow_flag(), false);
        assert_eq!(c.get_negative_flag(), true);
    }

    #[test]
    fn adc_9() {
        let c = test_adc(-66_i8 as u8, -65_i8 as u8, false);
        assert_eq!(c.reg_acc, 125);
        assert_eq!(c.get_carry_flag(), true);
        assert_eq!(c.get_overflow_flag(), true);
    }

    #[test]
    fn adc_10() {
        let c = test_adc(0, 0, false);
        assert_eq!(c.reg_acc, 0);
        assert_eq!(c.get_carry_flag(), false);
        assert_eq!(c.get_overflow_flag(), false);
        assert_eq!(c.get_zero_flag(), true);
        assert_eq!(c.get_negative_flag(), false);
    }

    #[test]
    fn adc_11() {
        let c = test_adc(-10_i8 as u8, 10, false);
        assert_eq!(c.reg_acc, 0);
        assert_eq!(c.get_overflow_flag(), false);
        assert_eq!(c.get_zero_flag(), true);
    }

    #[test]
    fn adc_dec_1() {
        let c = test_dec_adc(0x79, 0x14, false);
        assert_eq!(c.reg_acc, 0x93);
    }

    #[test]
    fn sbc_1() {
        let c = test_sbc(5, 3, true);
        assert_eq!(c.reg_acc, 2);
        assert_eq!(c.get_carry_flag(), true);
        assert_eq!(c.get_zero_flag(), false);
        assert_eq!(c.get_negative_flag(), false);
    }

    #[test]
    fn sbc_2() {
        let c = test_sbc(5, 6, true);
        assert_eq!(c.reg_acc, -1_i8 as u8);
        assert_eq!(c.get_carry_flag(), false);
        assert_eq!(c.get_zero_flag(), false);
        assert_eq!(c.get_negative_flag(), true);
    }

    #[test]
    fn sbc_dec_1() {
        let c = test_dec_sbc(0x44, 0x29, true);
        assert_eq!(c.reg_acc, 0x15);
    }

    #[test]
    fn and_1() {
        let c = test_and(0b00110011, 0b11001101);
        assert_eq!(c.reg_acc, 0b00000001);
        assert_eq!(c.get_zero_flag(), false);
        assert_eq!(c.get_negative_flag(), false);
    }

    #[test]
    fn and_2() {
        let c = test_and(0, 0b11111111);
        assert_eq!(c.reg_acc, 0);
        assert_eq!(c.get_zero_flag(), true);
        assert_eq!(c.get_negative_flag(), false);
    }

    #[test]
    fn and_3() {
        let c = test_and(0b11111111, 0b10000000);
        assert_eq!(c.reg_acc, 0b10000000);
        assert_eq!(c.get_zero_flag(), false);
        assert_eq!(c.get_negative_flag(), true);
    }

    #[test]
    fn ora_1() {
        let c = test_ora(0b00110011, 0b11001101);
        assert_eq!(c.reg_acc, 0b11111111);
        assert_eq!(c.get_zero_flag(), false);
        assert_eq!(c.get_negative_flag(), true);
    }

    #[test]
    fn ora_2() {
        let c = test_ora(0, 0);
        assert_eq!(c.reg_acc, 0);
        assert_eq!(c.get_zero_flag(), true);
        assert_eq!(c.get_negative_flag(), false);
    }

    #[test]
    fn ora_3() {
        let c = test_ora(0b10000000, 0b10000000);
        assert_eq!(c.reg_acc, 0b10000000);
        assert_eq!(c.get_zero_flag(), false);
        assert_eq!(c.get_negative_flag(), true);
    }

    #[test]
    fn eor_1() {
        let c = test_eor(0b00110011, 0b11001101);
        assert_eq!(c.reg_acc, 0b11111110);
        assert_eq!(c.get_zero_flag(), false);
        assert_eq!(c.get_negative_flag(), true);
    }

    #[test]
    fn eor_2() {
        let c = test_eor(0, 0);
        assert_eq!(c.reg_acc, 0);
        assert_eq!(c.get_zero_flag(), true);
        assert_eq!(c.get_negative_flag(), false);
    }

    #[test]
    fn eor_3() {
        let c = test_eor(0, 0b10000000);
        assert_eq!(c.reg_acc, 0b10000000);
        assert_eq!(c.get_zero_flag(), false);
        assert_eq!(c.get_negative_flag(), true);
    }

    #[test]
    fn cmp_1() {
        let c = test_cmp(0x01, 0xFF);
        assert_eq!(c.get_carry_flag(), false);
        assert_eq!(c.get_negative_flag(), false);
        assert_eq!(c.get_zero_flag(), false);
    }

    #[test]
    fn cmp_2() {
        let c = test_cmp(0x7F, 0x80);
        assert_eq!(c.get_carry_flag(), false);
        assert_eq!(c.get_negative_flag(), true);
        assert_eq!(c.get_zero_flag(), false);
    }

    #[test]
    fn cmp_3() {
        let c = test_cmp(0x01, 0x01);
        assert_eq!(c.get_carry_flag(), true);
        assert_eq!(c.get_negative_flag(), false);
        assert_eq!(c.get_zero_flag(), true);
    }

    #[test]
    fn bit_1() {
        let c = test_bit(0b_0000_1111, 0b_1111_0000);
        assert_eq!(c.get_overflow_flag(), true);
        assert_eq!(c.get_negative_flag(), true);
        assert_eq!(c.get_zero_flag(), true);
    }

    #[test]
    fn bit_2() {
        let c = test_bit(0b_0000_1111, 0b_0111_0000);
        assert_eq!(c.get_overflow_flag(), true);
        assert_eq!(c.get_negative_flag(), false);
        assert_eq!(c.get_zero_flag(), true);
    }

    #[test]
    fn bit_3() {
        let c = test_bit(0b_0000_1111, 0b_1011_0000);
        assert_eq!(c.get_overflow_flag(), false);
        assert_eq!(c.get_negative_flag(), true);
        assert_eq!(c.get_zero_flag(), true);
    }

    #[test]
    fn bit_4() {
        let c = test_bit(0b_0000_1111, 0b_0011_0000);
        assert_eq!(c.get_overflow_flag(), false);
        assert_eq!(c.get_negative_flag(), false);
        assert_eq!(c.get_zero_flag(), true);
    }

    #[test]
    fn bit_5() {
        let c = test_bit(0b_0000_1111, 0b_0011_0001);
        assert_eq!(c.get_overflow_flag(), false);
        assert_eq!(c.get_negative_flag(), false);
        assert_eq!(c.get_zero_flag(), false);
    }

    // TODO: add test for infamous JMP boundary
}
