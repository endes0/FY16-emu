
use unicorn_engine::Unicorn;
use unicorn_engine::unicorn_const::Permission;

use crate::utils;



// Memory regions constants
//pub mod mem_map {
    // ROM (Flash memories)
    pub const ROM1_START: u64 = 0x0;
    pub const ROM1_REMAP: u64 = 0x20000000;
    pub const ROM2_START: u64 = 0x04000000;
    pub const ROM2_REMAP: u64 = 0x24000000;
    pub const ROM_LENGTH: usize = 0x800000;

    // RAM
    pub const RAM_START: u64 =  0x40000000;
    pub const RAM_REMAP0: u64 = 0x50000000;
    pub const RAM_REMAP1: u64 = 0x60000000;
    pub const RAM_REMAP2: u64 = 0x70000000;
    pub const RAM_LENGTH: usize = 128 * (1024 * 1024); // 128 MB

    // TCM
    // instr TCM of 32KB at 80000000
    // data TCM of 4KB at 0x80008000
    pub const INSTR_TCM_START: u64 = 0x80000000;
    pub const INSTR_TCM_LENGTH: usize = 32 * 1024; // 32 KB

    pub const DATA_TCM_START: u64 = 0x80008000;
    pub const DATA_TCM_LENGTH: usize = 4 * 1024; // 4 KB

    // Peripherals
    pub const CORE_START: u64 = 0xd0000000;
    pub const CORE_LENGTH: usize = 0x400000;

    pub const IO_UNK0_START: u64 = 0xd0400000;
    pub const IO_UNK0_LENGTH: usize = 0x2000;

    pub const IO_EHCI_HOST_START : u64 = 0xd0802000;
    pub const IO_EHCI_HOST_LENGTH: usize = 0x1000;

    pub const IO_UNK5_START: u64 = 0xe0001000;
    pub const IO_UNK5_LENGTH: usize = 0x1000;

    pub const IO_UNK9_START: u64 = 0xe0003000;
    pub const IO_UNK9_LENGTH: usize = 0x1000;

    pub const IO_EHCI_START : u64 = 0xe0800000;
    pub const IO_EHCI_LENGTH: usize = 0x1000;

    pub const IO_UNK1_START: u64 = 0xe0812000;
    pub const IO_UNK1_LENGTH: usize = 0x1000;

    pub const IO_SERIAL_START: u64 = 0xe0816000;
    pub const IO_SERIAL_LENGTH: usize = 0x1000;

    pub const IO_UNK2_START: u64 = 0xe0817000;
    pub const IO_UNK2_LENGTH: usize = 0x1000;

    pub const IO_UNK6_START: u64 = 0xe0819000;
    pub const IO_UNK6_LENGTH: usize = 0x1000;

    pub const IO_UNK7_START: u64 = 0xe081a000;
    pub const IO_UNK7_LENGTH: usize = 0x1000;

    pub const MSG_RAM_START: u64 = 0xe0c00000;
    pub const MSG_RAM_LENGTH: usize = 0x4000;

    pub const IO_UNK3_START: u64 = 0xf0000000;
    pub const IO_UNK3_LENGTH: usize = 0x1000;

    pub const IO_UNKF0071_START: u64 = 0xf0071000;
    pub const IO_UNKF0071_LENGTH: usize = 0x1000;

    pub const INT_REGS_START: u64 = 0xf0080000;
    pub const INT_REGS_LENGTH: usize = 0x1000;

    pub const IO_UNK8_START: u64 = 0xf0084000;
    pub const IO_UNK8_LENGTH: usize = 0x1000;

    pub const IO_UNK4_START: u64 = 0xf0081000;
    pub const IO_UNK4_LENGTH: usize = 0x1000;

    pub const IO_SFLU3_START: u64 = 0xf0088000;
    pub const IO_SFLU3_LENGTH: usize = 0x1000;

    pub fn map_memory(mc: &mut Unicorn<()>) {
        mc.mem_map(RAM_START, RAM_LENGTH, Permission::ALL).expect("failed to map RAM");
        utils::mirror_map(mc, RAM_REMAP0, RAM_LENGTH, RAM_START);
        utils::mirror_map(mc, RAM_REMAP1, RAM_LENGTH, RAM_START);
        utils::mirror_map(mc, RAM_REMAP2, RAM_LENGTH, RAM_START);
        mc.mem_map(INSTR_TCM_START, INSTR_TCM_LENGTH, Permission::ALL).expect("failed to map instr TCM");
        mc.mem_map(DATA_TCM_START, DATA_TCM_LENGTH, Permission::ALL).expect("failed to map data TCM");
        mc.mem_map(CORE_START, CORE_LENGTH, Permission::ALL).expect("failed to map core");
        utils::dummy_map(mc, "IO_UNK0".to_string(), IO_UNK0_START, IO_UNK0_LENGTH);
        utils::dummy_map(mc, "IO_EHCI_HOST".to_string(), IO_EHCI_HOST_START, IO_EHCI_HOST_LENGTH);
        utils::dummy_map(mc, "IO_UNK5".to_string(), IO_UNK5_START, IO_UNK5_LENGTH);
        utils::dummy_map(mc, "IO_UNK9".to_string(), IO_UNK9_START, IO_UNK9_LENGTH);
        utils::dummy_map(mc, "IO_EHCI".to_string(), IO_EHCI_START, IO_EHCI_LENGTH);
        utils::dummy_map(mc, "IO_UNK1".to_string(), IO_UNK1_START, IO_UNK1_LENGTH);
        utils::dummy_map(mc, "IO_UNK2".to_string(), IO_UNK2_START, IO_UNK2_LENGTH);
        utils::dummy_map(mc, "IO_UNK6".to_string(), IO_UNK6_START, IO_UNK6_LENGTH);
        utils::dummy_map(mc, "IO_UNK7".to_string(), IO_UNK7_START, IO_UNK7_LENGTH);
        mc.mem_map(MSG_RAM_START, MSG_RAM_LENGTH, Permission::ALL).expect("failed to map msg ram");
        utils::dummy_map(mc, "INT_REGS".to_string(), INT_REGS_START, INT_REGS_LENGTH);
        utils::dummy_map(mc, "SLFU3".to_string(), IO_SFLU3_START, IO_SFLU3_LENGTH);
    }

//}