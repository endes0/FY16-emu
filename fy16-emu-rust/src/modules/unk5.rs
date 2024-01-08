use log::trace;
use unicorn_engine::Unicorn;

use crate::utils::Module;
use std::cell::RefCell;
use std::sync::Arc;

pub struct Unk5 {}

impl Unk5 {
    fn unk_read(mc: &mut Unicorn<()>, addr: u64, _size: usize) -> u64 {
        match addr {
            0x0 => {
                let intno = 0x67;
                // (uVar1 >> 0x10 & 0x7f) + 0x20;
                let val = (intno - 0x20) << 0x10;
                trace!(
                    "IO_UNK5: read from 0x{:x} = 0x{:x}  (PC: {:x})",
                    addr,
                    val,
                    mc.reg_read(unicorn_engine::RegisterARM::PC).unwrap()
                );
                return val;
            }
            _ => {
                trace!(
                    "IO_UNK5: read from 0x{:x} (PC: {:x})",
                    addr,
                    mc.reg_read(unicorn_engine::RegisterARM::PC).unwrap()
                );
                return 0;
            }
        }
    }

    fn unk_write(mc: &mut Unicorn<()>, addr: u64, _size: usize, value: u64) {
        trace!(
            "IO_UNK5: write to 0x{:x} = 0x{:x}  (PC: {:x})",
            addr,
            value,
            mc.reg_read(unicorn_engine::RegisterARM::PC).unwrap()
        );
    }
}

impl Module for Unk5 {
    fn load(self, mc: &mut Unicorn<()>) -> Arc<RefCell<Self>> {
        mc.mmio_map(
            crate::mem_map::IO_UNK5_START,
            crate::mem_map::IO_UNK5_LENGTH,
            Some(Self::unk_read),
            Some(Self::unk_write),
        )
        .expect("failed to map ASICIOU");

        Arc::new(RefCell::new(self))
    }
}
