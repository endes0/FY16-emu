use std::io::Write;
use unicorn_engine::Unicorn;
use log::trace;

use crate::utils::Module;

pub struct Unkf71 {
    // buf
    buf: Vec<u8>,
    n: u32,
}

impl Unkf71 {
    pub fn new() -> Unkf71 {
        Unkf71 {
            buf: Vec::new(),
            n: 0,
        }
    }

    fn unk_read(mc: &mut Unicorn<()>, addr: u64, _size: usize) -> u64 {
        match addr {
            0x2 => return 0x20,
            _ => {
                trace!("unkf71: read from 0x{:x} (PC: {:x})", addr, mc.reg_read(unicorn_engine::RegisterARM::PC).unwrap());
                return 0;
            }
        }
    }

    fn unk_write(&mut self, mc: &mut Unicorn<()>, addr: u64, _size: usize, value: u64) {
        match addr {
            0x490 => self.buf.push(value as u8),
            0x48e => {
                // Flush to a file
                let mut file = std::fs::File::create(format!("unkf71/{}.bin", self.n)).expect("failed to create file");
                file.write_all(&self.buf).expect("failed to write file");
                trace!("unkf71: 0x490 buffer flushed (size: {})", self.buf.len());
                self.buf.clear();
                self.n += 1;
                trace!("unkf71: write to 0x{:x} = 0x{:x}  (PC: {:x})", addr, value, mc.reg_read(unicorn_engine::RegisterARM::PC).unwrap());
            },
            _ => trace!("unkf71: write to 0x{:x} = 0x{:x}  (PC: {:x})", addr, value, mc.reg_read(unicorn_engine::RegisterARM::PC).unwrap())
        }
    }
}

impl Module for Unkf71 {
    fn load(mut self, mc: & mut Unicorn<()>) {
        let w_clbk = move |uc: &mut Unicorn<()>, addr: u64, _size: usize, value: u64| {
            self.unk_write(uc, addr, _size, value);
        };
        mc.mmio_map(crate::mem_map::IO_UNKF0071_START, crate::mem_map::IO_UNKF0071_LENGTH, Some(Self::unk_read), Some(w_clbk)).expect("failed to map unkf00071");
    }
}