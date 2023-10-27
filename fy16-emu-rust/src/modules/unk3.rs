use unicorn_engine::Unicorn;
use log::trace;

use crate::utils::Module;

pub struct Unk3 {
    
}

impl Unk3 {
    fn unk_read(mc: &mut Unicorn<()>, addr: u64, _size: usize) -> u64 {
        match addr {
            0x21 => return 0x8,
            0x72 => return 0x10,
            _   => {
                trace!("ASICIOU: read from 0x{:x} (PC: {:x})", addr, mc.reg_read(unicorn_engine::RegisterARM::PC).unwrap());
                return 0;
            }
        }
    }

    fn unk_write(mc: &mut Unicorn<()>, addr: u64, _size: usize, value: u64) {
        trace!("ASICIOU: write to 0x{:x} = 0x{:x}  (PC: {:x})", addr, value, mc.reg_read(unicorn_engine::RegisterARM::PC).unwrap());
    }
}

impl Module for Unk3 {
    fn load(self, mc: &mut Unicorn<()>) {
        mc.mmio_map(crate::mem_map::IO_ASICIOU_START, crate::mem_map::IO_ASICIOU_LENGTH, Some(Self::unk_read), Some(Self::unk_write)).expect("failed to map ASICIOU");
    }
}