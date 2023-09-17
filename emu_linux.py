from unicorn import *
from unicorn.arm_const import *
from udbserver import udbserver

from emu.utils import dummy_map, dummy_log, load_mem_file, dump_mem_file
from emu.mem_map import *
from emu.modules.serial import serial_read, serial_write
from emu.modules.unknows import unk3_read, unk3_write, unk4_read, unk4_write, unk8_read, unk8_write, unkf0071_read, unkf0071_write

blocks_log = open('out/blocks.log', 'w')

mu = Uc(UC_ARCH_ARM, UC_MODE_ARM926)

# map memory regions
map_memory(mu)

# hook invalid memory access
def hook_mem_invalid(mu, access, address, size, value, user_data):
    print("Invalid memory access at 0x%x, data size = %u, data value = 0x%x" %(address, size, value))
    # print values of registers
    print(">>> CPU context")
    print(">>> PC = 0x%x" %mu.reg_read(UC_ARM_REG_PC))
    for reg in range(UC_ARM_REG_R0, UC_ARM_REG_R12 + 1):
        rnum = reg - UC_ARM_REG_R0
        print(">>> R%d = 0x%x" %(rnum, mu.reg_read(reg)))
    print(">>> SP = 0x%x" %mu.reg_read(UC_ARM_REG_SP))
    dummy_map(mu, "FAKE_%x" % (address & 0xFFFFF000), address & 0xFFFFF000, 0x1000)
    udbserver(mu, 1234, 0)
    return True

mu.hook_add(UC_HOOK_MEM_INVALID, hook_mem_invalid)

mu.mmio_map(IO_SERIAL_ADDR, IO_SERIAL_LENGHT, serial_read, None, serial_write, None)
mu.mmio_map(IO_UNK3_ADDR, IO_UNK3_LENGHT, unk3_read, None, unk3_write, None)
mu.mmio_map(IO_UNK4_ADDR, IO_UNK4_LENGHT, unk4_read, None, unk4_write, None)
mu.mmio_map(IO_UNK8_ADDR, IO_UNK8_LENGHT, unk8_read, None, unk8_write, None)
mu.mmio_map(IO_UNKF0071_ADDR, IO_UNKF0071_LENGHT, unkf0071_read, None, unkf0071_write, None)

# load roms
#load_mem_file(mu, ROM1_ADDR, ROM_LENGHT, 'roms/rom1.bin')
load_mem_file(mu, 0x40007bc0, ROM_LENGHT, 'roms/ic1_lp_t.bin', 0x110000, True)
load_mem_file(mu, ROM1_REMAP_ADDR, ROM_LENGHT, 'roms/rom1.bin')
load_mem_file(mu, ROM2_ADDR, ROM_LENGHT, 'roms/rom2.bin')


def hook_block(uc, address, size, user_data):
    blocks_log.write("0x%x\n" %address)
    blocks_log.flush()

#mu.hook_add(UC_HOOK_BLOCK, hook_block)

def hook_code(uc, address, size, user_data):
    if address == 0xc000e18c:
        # stop
        mu.emu_stop()
        return False

#mu.hook_add(UC_HOOK_CODE, hook_code)

# hook CPU exception
def hook_exception(mu, intno, data):
    print(">>> Exception: %d" %intno)
    print(">>> PC = 0x%x" %mu.reg_read(UC_ARM_REG_PC))

    # skip instruction
    mu.reg_write(UC_ARM_REG_PC, mu.reg_read(UC_ARM_REG_PC) + 4)
    mu.emu_stop()
    return False

mu.hook_add(UC_HOOK_INTR, hook_exception)

# TODO: Jiffies or it will be stuck at calibrate_delay
# start emulation
try:
    udbserver(mu, 1234, 0)
    mu.emu_start(0x40007bc0, 0xc0000000)#, UC_SECOND_SCALE * 120)
except UcError as e:
    print("ERROR: %s" % e)
    # print pc
    print(">>> PC = 0x%x" %mu.reg_read(UC_ARM_REG_PC))


# dump ram
dump_mem_file(mu, RAM_ADDR, RAM_LENGHT, 'out/ram.bin')
#dump_mem_file(mu, UNKRAM_ADDR, UNKRAM_LENGHT, 'out/unkram.bin')

blocks_log.close()