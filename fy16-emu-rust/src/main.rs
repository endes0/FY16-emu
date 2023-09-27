use log::warn;
use unicorn_engine::{Unicorn, RegisterARM};
use unicorn_engine::unicorn_const::{Arch, Mode, uc_error, HookType, MemType};
use simplelog::*;

use std::fs::File;

use crate::utils::{Module, dummy_map};

mod mem_map;
mod utils;

mod modules;

fn hook_mem_invalid(mu: &mut Unicorn<()>, _access: MemType, address: u64, _size: usize, _value: i64) -> bool {
    warn!("Invalid memory access at 0x{:x}", address);

    // Fake map
    dummy_map(mu, format!("FAKE_{:x}", address & 0xFFFFF000), address & 0xFFFFF000, 0x1000);
    true
}

fn hook_code(uc: &mut Unicorn<()>, address: u64, _size: u32) {
    match address {
        0x1560 | 0x1804 | 0x6094 => println!("memcpy from: 0x{:x}, to: 0x{:x}, size: 0x{:x}", uc.reg_read(RegisterARM::R0).unwrap(), uc.reg_read(RegisterARM::R1).unwrap(), uc.reg_read(RegisterARM::R2).unwrap()),
        0x1615c => println!("cmp1: {:x} {:x}", uc.reg_read(RegisterARM::R7).unwrap(), uc.reg_read(RegisterARM::R10).unwrap()),

        // Crappy skip hack
        0x11000 => {uc.reg_write(RegisterARM::PC, 0x11010).expect("failed to write register"); println!("Skip tcm")}, //Skip TCM enable
        0x1551c => uc.reg_write(RegisterARM::PC, 0x15544).expect("failed to write register"),
        _ => {}
    }
}

fn main() {
    CombinedLogger::init(
        vec![
            TermLogger::new(LevelFilter::Warn, Config::default(), TerminalMode::Mixed, ColorChoice::Auto),
            WriteLogger::new(LevelFilter::Trace, Config::default(), File::create("emu.log").unwrap()),
        ]
    ).unwrap();

    let mut unicorn = Unicorn::new(Arch::ARM, Mode::ARM1176).expect("failed to initialize Unicorn instance");
    let emu = &mut unicorn;

    mem_map::map_memory(emu);

    emu.add_mem_hook(HookType::MEM_INVALID, 1, 0, hook_mem_invalid).expect("failed to add memory hook");
    emu.add_code_hook(1, 0, hook_code).expect("failed to add code hook");

    // Load modules
    let serial = modules::serial::Serial {};
    let unk3 = modules::unk3::Unk3 {};
    let unk4 = modules::unk4::Unk4 {};
    let unk8 = modules::unk8::Unk8 {};
    let unk71 = modules::unkf71::Unkf71::new();

    serial.load(emu);
    unk3.load(emu);
    unk4.load(emu);
    unk8.load(emu);
    unk71.load(emu);

    // Load roms
    utils::load_mem_file(emu, crate::mem_map::ROM1_START, crate::mem_map::ROM_LENGTH, "roms/rom1.bin", None, false);
    utils::mirror_map(emu, mem_map::ROM1_REMAP, mem_map::ROM_LENGTH, mem_map::ROM1_START);
    utils::load_mem_file(emu, mem_map::ROM2_START, mem_map::ROM_LENGTH, "roms/rom2.bin", None, false);
    utils::mirror_map(emu, mem_map::ROM2_REMAP, mem_map::ROM_LENGTH, mem_map::ROM2_START);

    // Start emulation
    let res = emu.emu_start(mem_map::ROM1_START, mem_map::RAM_LENGTH as u64, 0, 0);

    // Check if err INSN_INVALID
    if res.is_err() {
        let err = res.err().unwrap();
        if err == uc_error::INSN_INVALID {
            println!("Invalid instruction at 0x{:x}", emu.reg_read(RegisterARM::PC).unwrap());
        } else {
            println!("Error: {:?}", err);
        }
    }

}
