use unicorn_engine::Unicorn;
use log::trace;

use crate::utils::Module;

// Too simple implementation of SuperH serial
pub struct Serial {
    
}

impl Serial {
    pub fn serial_read(mc: &mut Unicorn<()>, addr: u64, _size: usize) -> u64 {
        match addr {
            0x10 => return 0x20 | 0x60, // UARTFR
            _ => {
                trace!("serial: read from 0x{:x} (PC: {:x})", addr, mc.reg_read(unicorn_engine::RegisterARM::PC).unwrap());
                return 0;
            }
        }
    }

    pub fn serial_write(mc: &mut Unicorn<()>, addr: u64, _size: usize, value: u64) {
        match addr {
            0x10 => return, // UARTFR
            0xc => print!("{}", value as u8 as char),
            _ => trace!("serial: write to 0x{:x} = 0x{:x}  (PC: {:x})", addr, value, mc.reg_read(unicorn_engine::RegisterARM::PC).unwrap()),
        }
    }
}

impl Module for Serial {
    fn load(self, mc: &mut Unicorn<()>) {
        mc.mmio_map(crate::mem_map::IO_SERIAL_START, crate::mem_map::IO_SERIAL_LENGTH, Some(Self::serial_read), Some(Self::serial_write)).expect("failed to map serial");
    }
}