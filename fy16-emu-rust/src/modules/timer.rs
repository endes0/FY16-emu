use std::cell::RefCell;
use std::sync::Arc;
use std::vec;

use log::trace;
use unicorn_engine::unicorn_const::Permission;
use unicorn_engine::Unicorn;

use crate::utils::Module;

// Too simple and cranky implementation of a timer
pub struct Timer {
    cycles: u64,
    target_cycles: u64,
    pub started: bool,
}

impl Timer {
    fn timer_hook_code(&mut self, uc: &mut Unicorn<()>, _address: u64, _size: u32) {
        //trace!("timer hook code at 0x{:x}", address);
        if !self.started {
            return;
        }
        self.cycles += 1;
        if self.cycles >= self.target_cycles {
            self.cycles = 0;
            trace!("timer interrupt");
            uc.set_pc(0x45000000).expect("failed to set PC");
        }
    }

    pub fn new() -> Self {
        Self {
            cycles: 0,
            target_cycles: 100000,
            started: false,
        }
    }
}

impl Module for Timer {
    fn load(self, mc: &mut Unicorn<()>) -> Arc<RefCell<Self>> {
        let self_ref = Arc::new(RefCell::new(self));
        let slef_ref_clone = self_ref.clone();

        //mc.mem_map(0x90000000, 0x1000, Permission::ALL)
        //    .expect("failed to map memory");
        let bytes = vec![0x08, 0x00, 0x00, 0xef];
        //let bytes = vec![0xef, 0x00, 0x00, 0x08];
        mc.mem_write(0x45000000, &bytes)
            .expect("failed to write memory");

        mc.add_code_hook(
            1,
            0,
            move |uc: &mut Unicorn<()>, address: u64, _size: u32| {
                self_ref.borrow_mut().timer_hook_code(uc, address, _size);
            },
        )
        .expect("failed to add hook");

        slef_ref_clone.clone()
    }
}
