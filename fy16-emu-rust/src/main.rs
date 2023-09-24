use unicorn_engine::{Unicorn, RegisterARM};
use unicorn_engine::unicorn_const::{Arch, Mode, Permission, HookType, MemType};

mod mem_map;
mod utils;

mod modules;

fn hook_mem_invalid(_mu: &mut Unicorn<()>, _access: MemType, address: u64, _size: usize, _value: i64) -> bool {
    println!("Invalid memory access at 0x{:x}", address);
    false
}

fn main() {
    let mut unicorn = Unicorn::new(Arch::ARM, Mode::ARM1176).expect("failed to initialize Unicorn instance");
    let emu = &mut unicorn;

    mem_map::map_memory(emu);

    emu.add_mem_hook(HookType::MEM_INVALID, 0, 0, hook_mem_invalid).expect("failed to add memory hook");

    let modules: Vec<&dyn utils::Module> = vec![
        &modules::serial::Serial {},
        //&modules::ehci::Ehci {},
        //&modules::ehci_host::EhciHost {},
    ];

    for module in modules {
        module.load(emu);
    }


}
