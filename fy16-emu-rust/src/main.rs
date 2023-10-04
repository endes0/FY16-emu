use log::{warn, error};
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

        //0x45e43978 =>  udbserver::udbserver(uc, 1234, 0).expect("Failed to start udbserver"),

        // crappy inject ram dump
        0x11944 => {
            warn!("Injecting ram dump");
            utils::load_mem_file(uc, 0x45100000, 0xa00000, "roms/dump_1.bin", None, true);
            utils::load_mem_file(uc, 0x45b00000, 0xa00000, "roms/dump_2.bin", None, true);
        }

        // Crappy skip hack
        0x11000 => {uc.reg_write(RegisterARM::PC, 0x11010).expect("failed to write register"); println!("Skip tcm")}, //Skip TCM enable
        0x1551c => uc.reg_write(RegisterARM::PC, 0x15544).expect("failed to write register"),
        0xffff0064 => println!("PC: 0x{:x} R12: {:x}", address, uc.reg_read(RegisterARM::R12).unwrap()),
        //0x80000000..=0xFFFFFFFF => println!("PC: 0x{:x}", address),
        _ => {}
    }
}

fn hook_intr(uc: &mut Unicorn<()>, intno: u32) {
    match intno {
        2 => {
            let pc = uc.reg_read(RegisterARM::PC).unwrap() - 4;
            let cpsr = uc.reg_read(RegisterARM::CPSR).unwrap();
            let vals = uc.mem_read_as_vec(pc, 3).unwrap();
            let val = (vals[0] as u32) | ((vals[1] as u32) << 8) | ((vals[2] as u32) << 16);
            warn!("Software interrupt 0x{:x} (PC 0x{:x}, CPSR: 0x{:x})", val, pc, cpsr);

            // copy cpsr to spsr
            uc.reg_write(RegisterARM::SPSR, cpsr).expect("failed to write register");
            // set mode svc in cpsr
            uc.reg_write(RegisterARM::CPSR, (cpsr & !0xF) | 0x13).expect("failed to write register");
            // set r14 to pc+4
            uc.reg_write(RegisterARM::R14, pc + 4).expect("failed to write register");

            //We should set PC to 0xffff0000 + 0x8, wich should be decoded by the MMU as a coarsed table entry at 454043c0, but it's not working.
            // 0xFFFFxxxx is decoded to 0x80000000 + xxxx (We go to the TCM)
            //uc.reg_write(RegisterARM::PC, 0x80000008).expect("failed to write register");
            uc.reg_write(RegisterARM::PC, 0xFFFF0008).expect("failed to write register");

            //utils::dump_mem_file(uc, mem_map::INSTR_TCM_START, mem_map::INSTR_TCM_LENGTH, "tcm.bin")
        },
        4 => {
            error!("Skipping interrupt 4 (Data abort)");
            uc.reg_write(RegisterARM::PC, uc.reg_read(RegisterARM::PC).unwrap() + 4).expect("failed to write register");
        },
        _ => {
            error!("Unhandled interrupt: {} (PC: 0x{:x})", intno, uc.reg_read(RegisterARM::PC).unwrap());
            // print sp
            println!("SP: 0x{:x}", uc.reg_read(RegisterARM::SP).unwrap());
            // print R0-R10
            for i in 0..=10 {
                println!("R{}: 0x{:x}", i, uc.reg_read(i + i32::from(RegisterARM::R0)).unwrap());
            }

            // print a stack dump
            let sp = uc.reg_read(RegisterARM::SP).unwrap();
            let mut buf = [0u8; 4];
            for i in 0..=0x20 {
                uc.mem_read(sp + (i * 4), &mut buf).expect("failed to read memory");
                println!("0x{:x}: 0x{:x}", sp + (i * 4), u32::from_le_bytes(buf));
            }

            // Stop
            uc.emu_stop().expect("failed to stop emulation");
        },
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
    emu.add_intr_hook(hook_intr).expect("failed to add interrupt hook");

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

            // Print PC
            println!("PC: 0x{:x}", emu.reg_read(RegisterARM::PC).unwrap());

        }
    }

}
