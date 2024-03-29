use log::{error, trace, warn};
use modules::{serial, timer, unk5};
use simplelog::*;
use unicorn_engine::unicorn_const::{uc_error, Arch, HookType, MemType, Mode};
use unicorn_engine::{RegisterARM, Unicorn};

use std::cell::RefCell;
use std::sync::Arc;

#[macro_use]
extern crate num_derive;
extern crate num;

#[macro_use]
extern crate bitfield;

use std::fs::File;

use crate::tkernel_utils::{AltTkFunIds, TkFunIds};
use crate::utils::{dummy_map, Module};

mod mem_map;
mod tkernel_utils;
mod utils;

mod modules;

struct Device {
    serial: Arc<RefCell<modules::serial::Serial>>,
    unk3: Arc<RefCell<modules::unk3::Unk3>>,
    unk4: Arc<RefCell<modules::unk4::Unk4>>,
    unk5: Arc<RefCell<modules::unk5::Unk5>>,
    unk8: Arc<RefCell<modules::unk8::Unk8>>,
    unk71: Arc<RefCell<modules::unkf71::Unkf71>>,
    sflu: Arc<RefCell<modules::sflu::Sflu>>,
    timer: Arc<RefCell<modules::timer::Timer>>,
}

fn hook_mem_invalid(
    mu: &mut Unicorn<()>,
    _access: MemType,
    address: u64,
    _size: usize,
    _value: i64,
) -> bool {
    warn!("Invalid memory access at 0x{:x}", address);

    // Fake map
    dummy_map(
        mu,
        format!("FAKE_{:x}", address & 0xFFFFF000),
        address & 0xFFFFF000,
        0x1000,
    );
    true
}

fn hook_code(dev: &mut Device, uc: &mut Unicorn<()>, address: u64, _size: u32) {
    match address {
        0x1560 | 0x1804 | 0x6094 => println!(
            "memcpy from: 0x{:x}, to: 0x{:x}, size: 0x{:x}",
            uc.reg_read(RegisterARM::R0).unwrap(),
            uc.reg_read(RegisterARM::R1).unwrap(),
            uc.reg_read(RegisterARM::R2).unwrap()
        ),
        0x1615c => println!(
            "cmp1: {:x} {:x}",
            uc.reg_read(RegisterARM::R7).unwrap(),
            uc.reg_read(RegisterARM::R10).unwrap()
        ),
        0x15d64 => println!(
            "invalidate_dcache: addr 0x{:x}-0x{:x} len {:x}",
            uc.reg_read(RegisterARM::R0).unwrap(),
            (uc.reg_read(RegisterARM::R0).unwrap() - uc.reg_read(RegisterARM::R1).unwrap()),
            uc.reg_read(RegisterARM::R1).unwrap()
        ),
        0x45e26b84 => println!(
            "tkernel progress: {}",
            uc.reg_read(RegisterARM::R0).unwrap()
        ),
        0x45c5da50 => println!("syscre reached"),
        0x45db84e0 => println!("usermain reached"),
        0x45e0b618 => println!("timer interrupt routine reached"),
        0x45e21ae4 => {
            dev.timer.borrow_mut().started = true;
            // hook code
            uc.add_code_hook(1, 0, hook_code_trace)
                .expect("failed to add code hook");
        }
        //0x15c08 => println!("FUN_00015c08: addr 0x{:x}-0x{:x} len {:x}", uc.reg_read(RegisterARM::R0).unwrap(), uc.reg_read(RegisterARM::R1).unwrap(), uc.reg_read(RegisterARM::R2).unwrap()),
        /*0x164dc => {
            let mem = uc.mem_read_as_vec(uc.reg_read(RegisterARM::R0).unwrap(), 4).unwrap();
            println!("FUN_000164dc: addr 0x{:x} 0x{:x}", uc.reg_read(RegisterARM::R0).unwrap(), uc.reg_read(RegisterARM::R1).unwrap());
            for dat in mem {
                println!("\t0x{:x}", dat);
            }
        },*/

        //0x45e43978 =>  udbserver::udbserver(uc, 1234, 0).expect("Failed to start udbserver"),

        /*0x11940 => {
            // stop emulation
            uc.emu_stop().expect("failed to stop emulation");
            // dump memory
            utils::dump_mem_file(uc, mem_map::RAM_START, mem_map::RAM_LENGTH, "out/ram.bin");
        },*/
        0x45e00c50 => {
            println!(
                "Register_int: {:x} 0x{:x}",
                uc.reg_read(RegisterARM::R0).unwrap(),
                uc.reg_read(RegisterARM::R1).unwrap()
            );
        }
        0x45490428 => {
            println!("debugPrint: 0x{:x}", uc.reg_read(RegisterARM::R0).unwrap());
        }
        0x45e0c92c => {
            println!("debugPrint: 0x{:x}", uc.reg_read(RegisterARM::R0).unwrap());
        }

        // crappy inject ram dump
        0x11944 => {
            warn!("Injecting ram dump");
            utils::load_mem_file(uc, 0x45100000, 0xa00000, "roms/dump_1.bin", None, true);
            utils::load_mem_file(uc, 0x45b00000, 0xa00000, "roms/dump_2.bin", None, true);
        }

        // Crappy skip hack
        0x11000 => {
            uc.reg_write(RegisterARM::PC, 0x11010)
                .expect("failed to write register");
            println!("Skip tcm")
        } //Skip TCM enable
        0x1551c => uc
            .reg_write(RegisterARM::PC, 0x15544)
            .expect("failed to write register"), // Skip wait function
        _ => {}
    }
}

fn hook_code_trace(uc: &mut Unicorn<()>, address: u64, _size: u32) {
    println!("0x{:x}", address);
}

fn hook_block(uc: &mut Unicorn<()>, address: u64, _size: u32) {
    println!("0x{:x}", address);
}

fn hook_intr(uc: &mut Unicorn<()>, intno: u32) {
    match intno {
        2 => {
            let pc = uc.reg_read(RegisterARM::PC).unwrap() - 4;
            let cpsr = uc.reg_read(RegisterARM::CPSR).unwrap();
            let r1 = uc.reg_read(RegisterARM::R1).unwrap();
            let vals = uc.mem_read_as_vec(pc, 3).unwrap();
            let val = (vals[0] as u32) | ((vals[1] as u32) << 8) | ((vals[2] as u32) << 16);

            if val == 0x6 {
                let funId = num::FromPrimitive::from_u64(r1).unwrap_or(TkFunIds::None);
                trace!("T-Kernel call(0x6) {} (FUNID: 0x{:x})", funId, r1);
            } else if val == 0xa {
                let funId = num::FromPrimitive::from_u64(r1).unwrap_or(AltTkFunIds::None);
                trace!("T-Kernel call(0x10) {} (FUNID: 0x{:x})", funId, r1);
            } else {
                warn!(
                    "Software interrupt 0x{:x} (PC 0x{:x}, FUNID: 0x{:x})",
                    val, pc, r1
                );
            }

            // copy cpsr to spsr
            uc.reg_write(RegisterARM::SPSR, cpsr)
                .expect("failed to write register");
            // set mode svc in cpsr
            uc.reg_write(RegisterARM::CPSR, (cpsr & !0xF) | 0x13)
                .expect("failed to write register");
            // set r14 to pc+4
            uc.reg_write(RegisterARM::R14, pc + 4)
                .expect("failed to write register");

            //We should set PC to 0xffff0000 + 0x8, wich should be decoded by the MMU as a coarsed table entry at 454043c0, but it's not working.
            // 0xFFFFxxxx is decoded to 0x80003000 + xxxx (We go to the TCM)
            //uc.reg_write(RegisterARM::PC, 0x80000008).expect("failed to write register");
            uc.reg_write(RegisterARM::PC, 0xFFFF0008)
                .expect("failed to write register");

            // enable PC tracing
            //uc.add_code_hook(1, 0, hook_code_trace).expect("failed to add code hook");
            //uc.add_block_hook(hook_block).expect("failed to add block hook");
        }
        4 => {
            error!(
                "Terminating at interrupt 4 (Data abort) (PC: {:x})",
                uc.reg_read(RegisterARM::PC).unwrap()
            );
            //udbserver::udbserver(uc, 1234, 0).expect("Failed to start udbserver");

            // Print registers
            println!("PC: 0x{:x}", uc.reg_read(RegisterARM::PC).unwrap());
            println!("SP: 0x{:x}", uc.reg_read(RegisterARM::SP).unwrap());
            for i in 0..=10 {
                println!(
                    "R{}: 0x{:x}",
                    i,
                    uc.reg_read(i + i32::from(RegisterARM::R0)).unwrap()
                );
            }

            // exit
            uc.emu_stop().expect("failed to stop emulation");
        }
        _ => {
            error!(
                "Unhandled interrupt: {} (PC: 0x{:x})",
                intno,
                uc.reg_read(RegisterARM::PC).unwrap()
            );
            // print sp
            println!("SP: 0x{:x}", uc.reg_read(RegisterARM::SP).unwrap());
            // print R0-R10
            for i in 0..=10 {
                println!(
                    "R{}: 0x{:x}",
                    i,
                    uc.reg_read(i + i32::from(RegisterARM::R0)).unwrap()
                );
            }

            // print a stack dump
            let sp = uc.reg_read(RegisterARM::SP).unwrap();
            let mut buf = [0u8; 4];
            for i in 0..=0x20 {
                uc.mem_read(sp + (i * 4), &mut buf)
                    .expect("failed to read memory");
                println!("0x{:x}: 0x{:x}", sp + (i * 4), u32::from_le_bytes(buf));
            }

            // Stop
            uc.emu_stop().expect("failed to stop emulation");
        }
    }
}

fn main() {
    CombinedLogger::init(vec![
        TermLogger::new(
            LevelFilter::Warn,
            Config::default(),
            TerminalMode::Mixed,
            ColorChoice::Auto,
        ),
        WriteLogger::new(
            LevelFilter::Trace,
            Config::default(),
            File::create("emu.log").unwrap(),
        ),
    ])
    .unwrap();

    let mut unicorn =
        Unicorn::new(Arch::ARM, Mode::ARM1176).expect("failed to initialize Unicorn instance");
    let emu = &mut unicorn;

    mem_map::map_memory(emu);

    // Load modules
    let serial = modules::serial::Serial {};
    let unk3 = modules::unk3::Unk3 {};
    let unk4 = modules::unk4::Unk4 {};
    let unk5 = modules::unk5::Unk5 {};
    let unk8 = modules::unk8::Unk8 {};
    let unk71 = modules::unkf71::Unkf71::new();
    let sflu = modules::sflu::Sflu::new();
    let timer = timer::Timer::new();

    let mut device = Device {
        serial: serial.load(emu),
        unk3: unk3.load(emu),
        unk4: unk4.load(emu),
        unk5: unk5.load(emu),
        unk8: unk8.load(emu),
        unk71: unk71.load(emu),
        sflu: sflu.load(emu),
        timer: timer.load(emu),
    };
    let dev_ref = Arc::new(RefCell::new(device));

    // Add hooks
    emu.add_mem_hook(HookType::MEM_INVALID, 1, 0, hook_mem_invalid)
        .expect("failed to add memory hook");
    emu.add_code_hook(
        1,
        0,
        move |uc: &mut Unicorn<()>, address: u64, _size: u32| {
            hook_code(&mut dev_ref.borrow_mut(), uc, address, _size);
        },
    )
    .expect("failed to add code hook");
    emu.add_intr_hook(hook_intr)
        .expect("failed to add interrupt hook");

    // Load roms
    utils::load_mem_file(
        emu,
        crate::mem_map::ROM1_START,
        crate::mem_map::ROM_LENGTH,
        "roms/rom1.bin",
        None,
        false,
    );
    utils::mirror_map(
        emu,
        mem_map::ROM1_REMAP,
        mem_map::ROM_LENGTH,
        mem_map::ROM1_START,
    );
    utils::load_mem_file(
        emu,
        mem_map::ROM2_START,
        mem_map::ROM_LENGTH,
        "roms/rom2.bin",
        None,
        false,
    );
    utils::mirror_map(
        emu,
        mem_map::ROM2_REMAP,
        mem_map::ROM_LENGTH,
        mem_map::ROM2_START,
    );

    // Start emulation
    let res = emu.emu_start(mem_map::ROM1_START, mem_map::RAM_LENGTH as u64, 0, 0);

    // Check if err INSN_INVALID
    if res.is_err() {
        let err = res.err().unwrap();
        if err == uc_error::INSN_INVALID {
            println!(
                "Invalid instruction at 0x{:x}",
                emu.reg_read(RegisterARM::PC).unwrap()
            );
        } else {
            println!("Error: {:?}", err);

            // Print PC
            println!("PC: 0x{:x}", emu.reg_read(RegisterARM::PC).unwrap());
        }
    }
}
