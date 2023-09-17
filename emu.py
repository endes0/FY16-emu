from unicorn import *
from unicorn.arm_const import *
from udbserver import udbserver

from emu.utils import dummy_map, load_mem_file, dump_mem_file, mirror_map
from emu.mem_map import *
from emu.modules.serial import serial_read, serial_write
from emu.modules.unknows import unk3_read, unk3_write, unk4_read, unk4_write, unk8_read, unk8_write, unkf0071_read, unkf0071_write

blocks_log = open('out/blocks.log', 'w')


mu = Uc(UC_ARCH_ARM, UC_MODE_ARM1176)

# map memory regions
map_memory(mu)

# hook invalid memory access
def hook_mem_invalid(mu, access, address, size, value, user_data):
    print("Invalid memory access at 0x%x, data size = %u, data value = 0x%x" %(address, size, value))
    # fake map
    #mu.mem_map(address & 0xFFFFF000, 0x1000)
    dummy_map(mu, "FAKE_%x" % (address & 0xFFFFF000), address & 0xFFFFF000, 0x1000)
    return True

mu.hook_add(UC_HOOK_MEM_INVALID, hook_mem_invalid)


mu.mmio_map(IO_SERIAL_ADDR, IO_SERIAL_LENGHT, serial_read, None, serial_write, None)
mu.mmio_map(IO_UNK3_ADDR, IO_UNK3_LENGHT, unk3_read, None, unk3_write, None)
mu.mmio_map(IO_UNK4_ADDR, IO_UNK4_LENGHT, unk4_read, None, unk4_write, None)
mu.mmio_map(IO_UNK8_ADDR, IO_UNK8_LENGHT, unk8_read, None, unk8_write, None)
mu.mmio_map(IO_UNKF0071_ADDR, IO_UNKF0071_LENGHT, unkf0071_read, None, unkf0071_write, None)

# load roms
load_mem_file(mu, ROM1_ADDR, ROM_LENGHT, 'roms/rom1.bin')
mirror_map(mu, ROM1_REMAP_ADDR, ROM_LENGHT, ROM1_ADDR)
load_mem_file(mu, ROM2_ADDR, ROM_LENGHT, 'roms/rom2.bin')
mirror_map(mu, ROM2_REMAP_ADDR, ROM_LENGHT, ROM2_ADDR)

def hook_block(uc, address, size, user_data):
    blocks_log.write("0x%x\n" %address)
    blocks_log.flush()

#mu.hook_add(UC_HOOK_BLOCK, hook_block)

def hook_code(uc, address, size, user_data):
    if address == 0x11940:
        print("Emulation stopped at 0x%x" %address)
        #udbserver(mu, 1234, 0)
        uc.emu_stop()
    #elif address == 0x118a0:
    #    udbserver(mu, 1234, 0)
    #elif address == 0x11940:
    #    uc.hook_add(UC_HOOK_BLOCK, hook_block)
    elif address == 0x12a4:
        print("Emulation trace at 0x%x" %address)
    elif address == 0x1560 or address == 0x1804 or address == 0x6094:
        print("memcpy from: 0x%x, to: 0x%x, size: 0x%x" %(mu.reg_read(UC_ARM_REG_R0), mu.reg_read(UC_ARM_REG_R1), mu.reg_read(UC_ARM_REG_R2)))
        return
    #elif address == 0x1614c:
    #    print("cmp: 0x%x 0x%x" %(mu.reg_read(UC_ARM_REG_R6), mu.reg_read(UC_ARM_REG_R9)))
    #    return
    elif address == 0x1615c:
        print("cmp1: 0x%x 0x%x" %(mu.reg_read(UC_ARM_REG_R7), mu.reg_read(UC_ARM_REG_R10)))
        return
    
    # super crappy hack to skip some code that is not emulated well (lazy me)
    elif address == 0x11000:
        # skip to 0x11010
        mu.reg_write(UC_ARM_REG_PC, 0x11010)
        return
    elif address == 0x1551c:
        # skip to 0x15544
        mu.reg_write(UC_ARM_REG_PC, 0x15544)
        return
    else:
        return
    
    # print values of registers
    print(">>> CPU context")
    for reg in range(UC_ARM_REG_R0, UC_ARM_REG_R12 + 1):
        rnum = reg - UC_ARM_REG_R0
        print(">>> R%d = 0x%x" %(rnum, mu.reg_read(reg)))

mu.hook_add(UC_HOOK_CODE, hook_code)


# start emulation
try:
    #udbserver(mu, 1234, 0)
    mu.emu_start(ROM1_ADDR, ROM_LENGHT)#, UC_SECOND_SCALE * 10)
except UcError as e:
    print("ERROR: %s" % e)
    # print pc
    print(">>> PC = 0x%x" %mu.reg_read(UC_ARM_REG_PC))

# dump ram
dump_mem_file(mu, RAM_ADDR, RAM_LENGHT, 'out/ram.bin')

blocks_log.close()