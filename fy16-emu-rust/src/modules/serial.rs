use unicorn_engine::Unicorn;

use crate::utils::Module;

// Too simple implementation of SuperH serial
pub struct Serial {
    
}

impl Serial {
    pub fn serial_read(mc: &mut Unicorn<()>, addr: u64, size: usize) -> u64 {
        match addr {
            0x10 => return 0x20 | 0x60, // UARTFR
            _ => {
                println!("serial: read from 0x{:x} (size: {})", addr, size);
                return 0;
            }
        }
    }

    pub fn serial_write(mc: &mut Unicorn<()>, addr: u64, size: usize, value: u64) {
        match addr {
            0x10 => return, // UARTFR
            0xc => print!("{}", value as u8 as char),
            _ => println!("serial: write to 0x{:x} (size: {}) = 0x{:x}", addr, size, value),
        }
    }
}

impl Module for Serial {
    fn load(&self, mc: &mut Unicorn<()>) {
        mc.mmio_map(crate::mem_map::IO_SERIAL_START, crate::mem_map::IO_SERIAL_LENGTH, Some(Self::serial_read), Some(Self::serial_write)).expect("failed to map serial");
    }
}