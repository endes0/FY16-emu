use unicorn_engine::Unicorn;
use log::trace;

use crate::utils::Module;

pub struct Unk4 {
    
}

impl Unk4 {
    fn unk_read(mc: &mut Unicorn<()>, addr: u64, _size: usize) -> u64 {
        match addr {
            0x0 => return 0x200,
            0x10 => return 0,
            _  => {
                trace!("unk4: read from 0x{:x} (PC: {:x})", addr, mc.reg_read(unicorn_engine::RegisterARM::PC).unwrap());
                return 0;
            }
        }
    }

    fn unk_write(mc: &mut Unicorn<()>, addr: u64, _size: usize, value: u64) {
        trace!("unk4: write to 0x{:x} = 0x{:x}  (PC: {:x})", addr, value, mc.reg_read(unicorn_engine::RegisterARM::PC).unwrap());
    }
}

impl Module for Unk4 {
    fn load(self, mc: &mut Unicorn<()>) {
        mc.mmio_map(crate::mem_map::IO_UNK4_START, crate::mem_map::IO_UNK4_LENGTH, Some(Self::unk_read), Some(Self::unk_write)).expect("failed to map unk4");
    }
}