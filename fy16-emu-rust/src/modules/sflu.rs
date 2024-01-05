use std::cell::RefCell;
use std::sync::Arc;

use crate::num;
use crate::num_derive::FromPrimitive;
use log::{trace, warn};
use strum_macros::Display;
use unicorn_engine::Unicorn;

use crate::utils::Module;

pub struct Sflu {
    current_cmd: Option<Commands>,
    pub current_addr: u32,
    pub current_chip: u32,
    pub data_buff: Vec<u8>,
}

#[derive(FromPrimitive, Display)]
enum Regs {
    SFLU_STATE_REGS = 0x0,
    SFLU_CTRL_REGS1 = 0x2,
    SFLU_CTRL_REGS2 = 0x4,
    SFLU_CTRL_REGS3 = 0x6,
    SFLU_TRIGER_REGS1 = 0x8,
    SFLU_TRIGER_REGS2 = 0xA,
    SFLU_PORT_CTRL = 0x10,
    SFLU_BUSY_EXT = 0x20,
    SFLU_SDR_WSIZE1 = 0x30,
    SFLU_SDR_WSIZE2 = 0x32,
    SFLU_SDR_ADDR1 = 0x34,
    SFLU_SDR_ADDR2 = 0x36,

    SFLU_SI_BUFF = 0x50,
    //    SFLU_SI_BUFF_L      = 0x50,
    SFLU_SO_BUFF1 = 0x60,
    SFLU_SO_BUFF2 = 0x62,
    SFLU_SO_BUFF3 = 0x64,
    SFLU_SO_BUFF4 = 0x66,

    SFLU3_CTRL_REG = 0x102,
}

#[derive(FromPrimitive, Display)]
enum Commands {
    WRITE_UNLOCK = 0x6,
    READ_STATUS = 0x5,
    PAGE_PROGRAM = 0x2,
}

bitfield! {
    struct SfluStateRegs(u32);
    impl Debug;
    u32;
    pub busy, set_busy: 0, 0;
}

bitfield! {
    struct SfluCtrlReg2(u32);
    impl Debug;
    u32;
    // XCE = L, msg we want send command to SF
    pub xce_chip_0, set_xce_chip_0: 0, 0;
    pub xce_chip_1, set_xce_chip_1: 8, 8;
}

bitfield! {
    struct SfluCtrlReg3(u32);
    impl Debug;
    u32;
    // XCE = L, msg we want send command to SF
    pub xce_chip_2, set_xce_chip_2: 0, 0;
    pub xce_chip_3, set_xce_chip_3: 8, 8;
}

impl Sflu {
    pub fn new() -> Self {
        Sflu {
            current_cmd: None,
            current_addr: 0,
            current_chip: 0,
            data_buff: Vec::new(),
        }
    }

    pub fn sflu_read(&mut self, mc: &mut Unicorn<()>, addr: u64, _size: usize) -> u64 {
        let reg: Option<Regs> = num::FromPrimitive::from_u64(addr);
        match reg {
            Some(Regs::SFLU_CTRL_REGS2) => {
                let mut ctrl_reg2 = SfluCtrlReg2(0);
                ctrl_reg2.set_xce_chip_0(true.into());
                ctrl_reg2.set_xce_chip_1(true.into());

                match self.current_chip {
                    0 => ctrl_reg2.set_xce_chip_0(false.into()),
                    1 => ctrl_reg2.set_xce_chip_0(false.into()),
                    _ => {}
                }

                ctrl_reg2.0.into()
            }
            Some(Regs::SFLU_CTRL_REGS3) => {
                let mut ctrl_reg3 = SfluCtrlReg3(0);
                ctrl_reg3.set_xce_chip_2(true.into());
                ctrl_reg3.set_xce_chip_3(true.into());

                match self.current_chip {
                    2 => ctrl_reg3.set_xce_chip_2(false.into()),
                    3 => ctrl_reg3.set_xce_chip_3(false.into()),
                    _ => {}
                }

                ctrl_reg3.0.into()
            }
            Some(Regs::SFLU_STATE_REGS) => {
                let mut state_reg = SfluStateRegs(0);
                state_reg.set_busy(false.into());
                state_reg.0.into()
            }
            Some(Regs::SFLU_SO_BUFF1) => {
                match self.current_cmd {
                    Some(Commands::READ_STATUS) => return 0x2, // 0x2 = write enable = 1. busy = 0
                    Some(_) => {
                        warn!(
                            "W25Q: unknow read on {} (PC: {:x})",
                            self.current_cmd.as_ref().unwrap(),
                            mc.reg_read(unicorn_engine::RegisterARM::PC).unwrap()
                        );
                        return 0;
                    }
                    None => {
                        warn!(
                            "W25Q: unknow read when none commad issued (PC: {:x})",
                            mc.reg_read(unicorn_engine::RegisterARM::PC).unwrap()
                        );
                        return 0;
                    }
                }
            }
            Some(_) => {
                trace!(
                    "SFLU: read from {} (PC: {:x})",
                    reg.unwrap(),
                    mc.reg_read(unicorn_engine::RegisterARM::PC).unwrap()
                );
                return 0;
            }
            None => {
                trace!(
                    "SFLU: read from unknow 0x{:x} (PC: {:x})",
                    addr,
                    mc.reg_read(unicorn_engine::RegisterARM::PC).unwrap()
                );
                return 0;
            }
        }
    }

    pub fn sflu_write(&mut self, mc: &mut Unicorn<()>, addr: u64, size: usize, value: u64) {
        let reg: Option<Regs> = num::FromPrimitive::from_u64(addr);
        match reg {
            Some(Regs::SFLU_CTRL_REGS2) => {
                // Set command to none and flush
                self.flush_transaction(mc);
                self.current_cmd = None;

                let ctrl_reg2 = SfluCtrlReg2(value as u32);
                if ctrl_reg2.xce_chip_0() == 0 {
                    self.current_chip = 0;
                } else if ctrl_reg2.xce_chip_1() == 0 {
                    self.current_chip = 1;
                }
            }
            // TODO: make only one match
            Some(Regs::SFLU_CTRL_REGS3) => {
                // Set command to none  and flush
                self.flush_transaction(mc);
                self.current_cmd = None;

                let ctrl_reg3 = SfluCtrlReg3(value as u32);
                if ctrl_reg3.xce_chip_2() == 0 {
                    self.current_chip = 2;
                } else if ctrl_reg3.xce_chip_3() == 0 {
                    self.current_chip = 3;
                }
            }
            Some(Regs::SFLU_SI_BUFF) => {
                if let Some(cmd) = &self.current_cmd {
                    match cmd {
                        Commands::PAGE_PROGRAM => {
                            for i in 0..size {
                                let val = value >> (i * 8);
                                self.data_buff.push(val as u8);
                            }
                        }
                        _ => {
                            warn!(
                                "W25Q: unknow write on INPUT BUFFER on {} (PC: {:x})",
                                cmd,
                                mc.reg_read(unicorn_engine::RegisterARM::PC).unwrap()
                            );
                        }
                    }

                    return;
                }

                let cmd = num::FromPrimitive::from_u64(value & 0xFF);
                self.current_cmd = cmd;
                match self.current_cmd {
                    Some(Commands::PAGE_PROGRAM) => {
                        if size > 1 {
                            for i in 1..size {
                                let val = value >> (i * 8);
                                self.data_buff.push(val as u8);
                            }
                        }
                    }
                    Some(_) => {
                        trace!(
                            "W25Q: cmd {} (PC: {:x})",
                            self.current_cmd.as_ref().unwrap(),
                            mc.reg_read(unicorn_engine::RegisterARM::PC).unwrap()
                        );
                    }
                    None => {
                        warn!(
                            "W25Q: cmd unknow 0x{:x} (PC: {:x})",
                            value,
                            mc.reg_read(unicorn_engine::RegisterARM::PC).unwrap()
                        );
                    }
                }
            }
            Some(_) => trace!(
                "SFLU: write to {} = 0x{:x}  (PC: {:x})",
                reg.unwrap(),
                value,
                mc.reg_read(unicorn_engine::RegisterARM::PC).unwrap()
            ),
            None => trace!(
                "SFLU: write to 0x{:x} = 0x{:x}  (PC: {:x})",
                addr,
                value,
                mc.reg_read(unicorn_engine::RegisterARM::PC).unwrap()
            ),
        }
    }

    fn flush_transaction(&mut self, mc: &mut Unicorn<()>) {
        if let Some(cmd) = &self.current_cmd {
            match cmd {
                Commands::PAGE_PROGRAM => {
                    // addr is the 3 first byte of the buffer
                    self.current_addr = self.data_buff[2] as u32
                        | ((self.data_buff[1] as u32) << 8)
                        | ((self.data_buff[0] as u32) << 16);
                    trace!(
                        "W25Q: WRITE to chip {} addr 0x{:x} data: {:x?}",
                        self.current_chip,
                        self.current_addr,
                        self.data_buff
                    );

                    // Update ROM mem
                    if self.current_chip == 0 {
                        let pos = (self.current_addr as u64) + crate::mem_map::ROM1_START;
                        mc.mem_write(pos, &self.data_buff)
                            .expect(format!("Failed to write to memory 0x{:x}", pos).as_str());
                    }

                    self.data_buff.clear();
                }
                _ => {}
            }
        }
    }
}

impl Module for Sflu {
    fn load(self, mc: &mut Unicorn<()>) -> Arc<RefCell<Self>> {
        let self_ref = Arc::new(RefCell::new(self));
        let self_ref_clone = self_ref.clone();
        let self_ref_clone2 = self_ref.clone();
        mc.mmio_map(
            crate::mem_map::IO_SFLU3_START,
            crate::mem_map::IO_SFLU3_LENGTH,
            Some(move |mc: &mut Unicorn<()>, addr: u64, size: usize| {
                return self_ref.borrow_mut().sflu_read(mc, addr, size);
            }),
            Some(
                move |mc: &mut Unicorn<()>, addr: u64, size: usize, value: u64| {
                    self_ref_clone
                        .borrow_mut()
                        .sflu_write(mc, addr, size, value)
                },
            ),
        )
        .expect("failed to map sflu");

        self_ref_clone2.clone()
    }
}
