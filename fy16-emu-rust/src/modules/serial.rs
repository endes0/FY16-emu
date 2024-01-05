use crate::num;
use crate::num_derive::FromPrimitive;
use log::trace;
use strum_macros::Display;
use unicorn_engine::Unicorn;

use std::cell::RefCell;
use std::sync::Arc;

use crate::utils::Module;

// Too simple implementation of SuperH serial
pub struct Serial {}

#[derive(FromPrimitive, Display)]
enum Regs {
    SCSM = 0x0,   // Serial port mode
    SCBR = 0x4,   // Baud rate
    SCSC = 0x8,   // Serial port control
    SCFTD = 0xc,  // Transmit FIFO data
    SCFS = 0x10,  // Status
    SCFRD = 0x14, // Receive FIFO data
    SCFC = 0x18,  // FIFO control
    SCFD = 0x1c,  // FIFO data count
    SCSPT = 0x20, // Serial port control
    SCLS = 0x24,  // Line status
}

impl Serial {
    pub fn serial_read(mc: &mut Unicorn<()>, addr: u64, _size: usize) -> u64 {
        let reg = num::FromPrimitive::from_u64(addr);
        match reg {
            Some(Regs::SCFS) => return 0x20 | 0x60,
            Some(_) => {
                trace!(
                    "serial: read from {} (PC: {:x})",
                    reg.unwrap(),
                    mc.reg_read(unicorn_engine::RegisterARM::PC).unwrap()
                );
                return 0;
            }
            None => {
                trace!(
                    "serial: read from unknow 0x{:x} (PC: {:x})",
                    addr,
                    mc.reg_read(unicorn_engine::RegisterARM::PC).unwrap()
                );
                return 0;
            }
        }
    }

    pub fn serial_write(mc: &mut Unicorn<()>, addr: u64, _size: usize, value: u64) {
        let reg = num::FromPrimitive::from_u64(addr);
        match reg {
            Some(Regs::SCFS) => return,
            Some(Regs::SCFTD) => print!("{}", value as u8 as char),
            Some(_) => trace!(
                "serial: write to {} = 0x{:x}  (PC: {:x})",
                reg.unwrap(),
                value,
                mc.reg_read(unicorn_engine::RegisterARM::PC).unwrap()
            ),
            None => trace!(
                "serial: write to 0x{:x} = 0x{:x}  (PC: {:x})",
                addr,
                value,
                mc.reg_read(unicorn_engine::RegisterARM::PC).unwrap()
            ),
        }
    }
}

impl Module for Serial {
    fn load(self, mc: &mut Unicorn<()>) -> Arc<RefCell<Self>> {
        mc.mmio_map(
            crate::mem_map::IO_SERIAL_START,
            crate::mem_map::IO_SERIAL_LENGTH,
            Some(Self::serial_read),
            Some(Self::serial_write),
        )
        .expect("failed to map serial");
        mc.mmio_map(
            crate::mem_map::IO_SERIAL1_START,
            crate::mem_map::IO_SERIAL1_LENGTH,
            Some(Self::serial_read),
            Some(Self::serial_write),
        )
        .expect("failed to map serial1");
        mc.mmio_map(
            crate::mem_map::IO_SERIAL2_START,
            crate::mem_map::IO_SERIAL2_LENGTH,
            Some(Self::serial_read),
            Some(Self::serial_write),
        )
        .expect("failed to map serial2");

        Arc::new(RefCell::new(self))
    }
}
