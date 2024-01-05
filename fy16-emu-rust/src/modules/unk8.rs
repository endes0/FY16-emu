use unicorn_engine::Unicorn;
use log::trace;

use crate::utils::Module;

use std::cell::RefCell;
use std::sync::Arc;

pub struct Unk8 {
    
}

impl Unk8 {
    fn unk_read(mc: &mut Unicorn<()>, addr: u64, _size: usize) -> u64 {
        match addr {
            0x800 => return 0x2,
            0x720 => return 0x40,
            _ => {
                trace!("unk8: read from 0x{:x} (PC: {:x})", addr, mc.reg_read(unicorn_engine::RegisterARM::PC).unwrap());
                return 0;
            }
        }
    }

    fn unk_write(mc: &mut Unicorn<()>, addr: u64, _size: usize, value: u64) {
        trace!("unk8: write to 0x{:x} = 0x{:x}  (PC: {:x})", addr, value, mc.reg_read(unicorn_engine::RegisterARM::PC).unwrap());
    }
}

impl Module for Unk8 {
    fn load(self, mc: &mut Unicorn<()>) -> Arc<RefCell<Self>> {
        mc.mmio_map(crate::mem_map::IO_UNK8_START, crate::mem_map::IO_UNK8_LENGTH, Some(Self::unk_read), Some(Self::unk_write)).expect("failed to map unk8");

        Arc::new(RefCell::new(self))
    }
}