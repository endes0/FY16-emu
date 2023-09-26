use unicorn_engine::Unicorn;
use log::trace;

use crate::utils::Module;

pub struct Unkf71 {
    
}

impl Unkf71 {
    fn unk_read(mc: &mut Unicorn<()>, addr: u64, _size: usize) -> u64 {
        match addr {
            0x2 => return 0x20,
            _ => {
                trace!("unkf71: read from 0x{:x} (PC: {:x})", addr, mc.reg_read(unicorn_engine::RegisterARM::PC).unwrap());
                return 0;
            }
        }
    }

    fn unk_write(mc: &mut Unicorn<()>, addr: u64, _size: usize, value: u64) {
        trace!("unkf71: write to 0x{:x} = 0x{:x}  (PC: {:x})", addr, value, mc.reg_read(unicorn_engine::RegisterARM::PC).unwrap());
    }
}

impl Module for Unkf71 {
    fn load(&self, mc: &mut Unicorn<()>) {
        mc.mmio_map(crate::mem_map::IO_UNKF0071_START, crate::mem_map::IO_UNKF0071_LENGTH, Some(Self::unk_read), Some(Self::unk_write)).expect("failed to map unkf00071");
    }
}