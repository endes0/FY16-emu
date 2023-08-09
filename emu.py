from unicorn import *
from unicorn.arm_const import *

blocks_log = open('out/blocks.log', 'w')
dummy_log = open('out/dummy.log', 'w')

def load_mem_file(mu, addr, lenght, path):
    with open(path, 'rb') as f:
        data = f.read()
        mu.mem_map(addr, lenght)
        mu.mem_write(addr, data)

def dump_mem_file(mu, addr, lenght, path):
    with open(path, 'wb') as f:
        f.write(mu.mem_read(addr, lenght))

def dummy_map(uc, name, addr, lenght):
    def dummy_read(mu, offset, size, user_data) -> int:
        dummy_log.write("%s;R;0x%x;%u\n" %(name, offset, size))
        return 0
    
    def dummy_write(mu, offset, size, value: int, user_data):
        dummy_log.write("%s;W;0x%x;%u;0x%x\n" %(name, offset, size, value))

    uc.mmio_map(addr, lenght, dummy_read, None, dummy_write, None)


# memory regions
ROM1_ADDR =         0x0
ROM2_ADDR =         0x04000000
ROM1_REMAP_ADDR =   0x20000000
ROM_LENGHT = 0x800000

RAM_ADDR = 0x40000000
RAM_LENGHT = 512 * (1024 * 1024) # 512 MB

UNKRAM_ADDR = 0x80000000
UNKRAM_LENGHT = 0x4000

CORE_ADDR = 0xd0000000
CORE_LENGHT = 0x400000

IO_UNK0_ADDR = 0xd0400000
IO_UNK0_LENGHT = 0x2000

IO_EHCI_HOST_ADDR = 0xd0802000
IO_EHCI_HOST_LENGHT = 0x1000

IO_UNK5_ADDR = 0xe0001000
IO_UNK5_LENGHT = 0x1000

IO_UNK9_ADDR = 0xe0003000
IO_UNK9_LENGHT = 0x1000

IO_EHCI_ADDR = 0xe0800000
IO_EHCI_LENGHT = 0x1000

IO_UNK1_ADDR = 0xe0812000
IO_UNK1_LENGHT = 0x1000

IO_SERIAL_ADDR = 0xe0816000
IO_SERIAL_LENGHT = 0x1000

IO_UNK2_ADDR = 0xe0817000
IO_UNK2_LENGHT = 0x1000

IO_UNK6_ADDR = 0xe0819000
IO_UNK6_LENGHT = 0x1000

IO_UNK7_ADDR = 0xe081a000
IO_UNK7_LENGHT = 0x1000

MSG_RAM_ADDR = 0xe0c00000
MSG_RAM_LENGHT = 0x4000

IO_UNK3_ADDR = 0xf0000000
IO_UNK3_LENGHT = 0x1000

IO_UNKF0071_ADDR = 0xf0071000
IO_UNKF0071_LENGHT =   0x1000

INT_REGS_ADDR = 0xf0080000
INT_REGS_LENGHT = 0x1000

IO_UNK8_ADDR = 0xf0084000
IO_UNK8_LENGHT = 0x1000

IO_UNK4_ADDR = 0xf0081000
IO_UNK4_LENGHT = 0x1000

SFLU3_ADDR = 0xf0088000
SFLU3_LENGHT = 0x1000


mu = Uc(UC_ARCH_ARM, UC_MODE_ARM1176)

# map memory regions
mu.mem_map(RAM_ADDR, RAM_LENGHT)
mu.mem_map(UNKRAM_ADDR, UNKRAM_LENGHT)
mu.mem_map(CORE_ADDR, CORE_LENGHT)
dummy_map(mu, "IO_UNK0", IO_UNK0_ADDR, IO_UNK0_LENGHT)
dummy_map(mu, "IO_UNK5", IO_UNK5_ADDR, IO_UNK5_LENGHT)
dummy_map(mu, "IO_UNK9", IO_UNK9_ADDR, IO_UNK9_LENGHT)
dummy_map(mu, "IO_EHCI_HOST", IO_EHCI_HOST_ADDR, IO_EHCI_HOST_LENGHT)
dummy_map(mu, "IO_EHCI", IO_EHCI_ADDR, IO_EHCI_LENGHT)
dummy_map(mu, "IO_UNK1", IO_UNK1_ADDR, IO_UNK1_LENGHT)
dummy_map(mu, "IO_UNK2", IO_UNK2_ADDR, IO_UNK2_LENGHT)
dummy_map(mu, "IO_UNK6", IO_UNK6_ADDR, IO_UNK6_LENGHT)
dummy_map(mu, "IO_UNK7", IO_UNK7_ADDR, IO_UNK7_LENGHT)
mu.mem_map(MSG_RAM_ADDR, MSG_RAM_LENGHT) # Dummy map causes boot loop
dummy_map(mu, "INT_REGS", INT_REGS_ADDR, INT_REGS_LENGHT)
dummy_map(mu, "SFLU3", SFLU3_ADDR, SFLU3_LENGHT)

# hook invalid memory access
def hook_mem_invalid(mu, access, address, size, value, user_data):
    print("Invalid memory access at 0x%x, data size = %u, data value = 0x%x" %(address, size, value))
    # fake map
    #mu.mem_map(address & 0xFFFFF000, 0x1000)
    dummy_map(mu, "FAKE_%x" % (address & 0xFFFFF000), address & 0xFFFFF000, 0x1000)
    return True

mu.hook_add(UC_HOOK_MEM_INVALID, hook_mem_invalid)

# hook serial port
def serial_read(mu, offset, size, user_data) -> int:
    if offset == 0x10:
        return 0x20 | 0x60
    else:
        print("Serial read at 0x%x, data size = %u" %(offset, size))
        return 0
    
def serial_write(mu, offset, size, value: int, user_data):
    if offset == 0x10:
        #print("Serial write at 0x%x, data size = %u, data value = 0x%x" %(offset, size, value))
        return
    elif offset == 0xc:
        print(chr(value), end='')
    else:
        print("Serial write at 0x%x, data size = %u" %(offset, size))

mu.mmio_map(IO_SERIAL_ADDR, IO_SERIAL_LENGHT, serial_read, None, serial_write, None)

# hook dummy unk3
def unk3_read(mu, offset, size, user_data) -> int:
    #print("Unk3 read at 0x%x, data size = %u" %(offset, size))
    if offset == 0x21:
        return 0x8
    if offset == 0x72:
        return 0x10
    dummy_log.write("%s;R;0x%x;%u\n" %("IO_unk3", offset, size))
    return 0

def unk3_write(mu, offset, size, value: int, user_data):
    #print("Unk3 write at 0x%x, data size = %u, data value = 0x%x" %(offset, size, value))
    dummy_log.write("%s;W;0x%x;%u;0x%x\n" %("IO_unk3", offset, size, value))
    return

mu.mmio_map(IO_UNK3_ADDR, IO_UNK3_LENGHT, unk3_read, None, unk3_write, None)

# hook dummy unk4
def unk4_read(mu, offset, size, user_data) -> int:
    #print("Unk4 read at 0x%x, data size = %u" %(offset, size))
    if offset == 0x0:
        return 0x200
    elif offset == 0x10:
        return 0
    dummy_log.write("%s;R;0x%x;%u\n" %("IO_unk4", offset, size))
    return 0

def unk4_write(mu, offset, size, value: int, user_data):
    #print("Unk4 write at 0x%x, data size = %u, data value = 0x%x" %(offset, size, value))
    dummy_log.write("%s;W;0x%x;%u;0x%x\n" %("IO_unk4", offset, size, value))
    return

mu.mmio_map(IO_UNK4_ADDR, IO_UNK4_LENGHT, unk4_read, None, unk4_write, None)

# hook dummy unk8
def unk8_read(mu, offset, size, user_data) -> int:
    #print("Unk8 read at 0x%x, data size = %u" %(offset, size))
    if offset == 0x800: 
        return 0x2
    elif offset == 0x720:
        return 0x40
    dummy_log.write("%s;R;0x%x;%u\n" %("IO_unk8", offset, size))
    return 0

def unk8_write(mu, offset, size, value: int, user_data):
    #print("Unk8 write at 0x%x, data size = %u, data value = 0x%x" %(offset, size, value))
    dummy_log.write("%s;W;0x%x;%u;0x%x\n" %("IO_unk8", offset, size, value))
    return

mu.mmio_map(IO_UNK8_ADDR, IO_UNK8_LENGHT, unk8_read, None, unk8_write, None)

# hook dummy unk IO_UNKF0071_ADDR
def unkf0071_read(mu, offset, size, user_data) -> int:
    #print("Unkf0071 read at 0x%x, data size = %u" %(offset, size))
    if offset == 0x2:
        return 0x20
    dummy_log.write("%s;R;0x%x;%u\n" %("IO_unkf0071", offset, size))
    return 0

def unkf0071_write(mu, offset, size, value: int, user_data):
    #print("Unkf0071 write at 0x%x, data size = %u, data value = 0x%x" %(offset, size, value))
    dummy_log.write("%s;W;0x%x;%u;0x%x\n" %("IO_unkf0071", offset, size, value))
    return

mu.mmio_map(IO_UNKF0071_ADDR, IO_UNKF0071_LENGHT, unkf0071_read, None, unkf0071_write, None)

# load roms
load_mem_file(mu, ROM1_ADDR, ROM_LENGHT, 'roms/rom1.bin')
load_mem_file(mu, ROM1_REMAP_ADDR, ROM_LENGHT, 'roms/rom1.bin')
load_mem_file(mu, ROM2_ADDR, ROM_LENGHT, 'roms/rom2.bin')

def hook_block(uc, address, size, user_data):
    blocks_log.write("0x%x\n" %address)
    blocks_log.flush()

#mu.hook_add(UC_HOOK_BLOCK, hook_block)

def hook_code(uc, address, size, user_data):
    if address == 0x11940:
        print("Emulation stopped at 0x%x" %address)
        uc.emu_stop()
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
    mu.emu_start(ROM1_ADDR, ROM_LENGHT)#, UC_SECOND_SCALE * 10)
except UcError as e:
    print("ERROR: %s" % e)
    # print pc
    print(">>> PC = 0x%x" %mu.reg_read(UC_ARM_REG_PC))

# dump ram
dump_mem_file(mu, RAM_ADDR, RAM_LENGHT, 'out/ram.bin')
dump_mem_file(mu, UNKRAM_ADDR, UNKRAM_LENGHT, 'out/unkram.bin')

blocks_log.close()