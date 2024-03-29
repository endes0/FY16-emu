

use unicorn_engine::Unicorn;
use unicorn_engine::unicorn_const::Permission;
use log::trace;
use std::fs::File;
use std::io::prelude::*;

use std::cell::RefCell;
use std::sync::Arc;

pub fn mirror_map(mc: &mut Unicorn<()>, start: u64, length: usize, mirror_addr:u64 ) {
    let mirror_read = move |uc: &mut Unicorn<()>, addr: u64, _size: usize| -> u64 {
        let mirror_addr = mirror_addr + addr;
        let mut buf = [0u8; 8];
        uc.mem_read(mirror_addr, &mut buf).expect("failed to mirror read");

        u64::from_le_bytes(buf)
    };

    let mirror_write = move |uc: &mut Unicorn<()>, addr: u64, _size: usize, value: u64| {
        let mirror_addr = mirror_addr + addr;
        let buf = value.to_le_bytes();
        uc.mem_write(mirror_addr, &buf).expect("failed to mirror write");
    };

    mc.mmio_map(start, length, Some(mirror_read), Some(mirror_write)).expect("failed to mirror map");   
}

pub fn dummy_map(mc: &mut Unicorn<()>, name: String, start: u64, length: usize) {

    let name2 = name.clone(); // TODO: find a better way to do this
    let dummy_read = move |uc: &mut Unicorn<()>, addr: u64, _size: usize| -> u64 {
        trace!("{}: read from 0x{:x} (PC: {:x})", name, addr, uc.reg_read(unicorn_engine::RegisterARM::PC).unwrap());
        0
    };

    let dummy_write = move |uc: &mut Unicorn<()>, addr: u64, _size: usize, value: u64| {
        trace!("{}: write to 0x{:x} = 0x{:x}  (PC: {:x})", name2, addr, value, uc.reg_read(unicorn_engine::RegisterARM::PC).unwrap());
    };

    mc.mmio_map(start, length, Some(dummy_read), Some(dummy_write)).expect("failed to dummy map");
}

pub fn load_mem_file(mc: &mut Unicorn<()>, addr: u64, length: usize, path: &'static str, offset: Option<u64>, is_mapped: bool) {
    // Open file
    let mut file = File::open(path).expect("failed to open file");
    if let Some(offset) = offset {
        file.seek(std::io::SeekFrom::Start(offset)).expect("failed to seek file");
    }
    if !is_mapped {
        mc.mem_map(addr, length, Permission::ALL).expect("failed to map memory");
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).expect("failed to read file");
    mc.mem_write(addr, &bytes).expect("failed to write memory");
}

pub fn dump_mem_file(mc: &mut Unicorn<()>, addr: u64, length: usize, path: &'static str) {
    // Create file
    let mut file = File::create(path).expect("failed to create file");
    let data = mc.mem_read_as_vec(addr, length).expect("failed to read memory");
    file.write_all(&data).expect("failed to write file");
}

pub trait Module {
    fn load(self, mc: &mut Unicorn<()>) -> Arc<RefCell<Self>>;
}