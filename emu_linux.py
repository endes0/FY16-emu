from unicorn import *
from unicorn.arm_const import *
from udbserver import udbserver

blocks_log = open('out/blocks.log', 'w')
dummy_log = open('out/dummy.log', 'w')

def load_mem_file(mu, addr, lenght, path, offset = 0, isMapped = False):
    with open(path, 'rb') as f:
        f.seek(offset)
        data = f.read()
        if not isMapped:
            mu.mem_map(addr, lenght)
        mu.mem_write(addr, data)

def dump_mem_file(mu, addr, lenght, path):
    with open(path, 'wb') as f:
        f.write(mu.mem_read(addr, lenght))

def dummy_map(uc, name, addr, lenght):
    def dummy_read(mu, offset, size, user_data) -> int:
        dummy_log.write("%s;R;0x%x;%u\n" %(name, offset, size))
        dummy_log.flush()
        return 0
    
    def dummy_write(mu, offset, size, value: int, user_data):
        dummy_log.write("%s;W;0x%x;%u;0x%x\n" %(name, offset, size, value))
        dummy_log.flush()

    uc.mmio_map(addr, lenght, dummy_read, None, dummy_write, None)

def patch_nop(mu, addr):
    mu.mem_write(addr, b'\x00\xf0\x20\xe3')

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


mu = Uc(UC_ARCH_ARM, UC_MODE_ARM926)

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

# hook serial port
def serial_read(mu, offset, size, user_data) -> int:
    if offset == 0x10:
        return 0x20 | 0x60
    else:
        print("Serial read at 0x%x, data size = %u" %(offset, size))
        return 0
    
def serial_write(mu, offset, size, value: int, user_data):
    if offset == 0x10:
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
    dummy_log.flush()
    return 0

def unk3_write(mu, offset, size, value: int, user_data):
    #print("Unk3 write at 0x%x, data size = %u, data value = 0x%x" %(offset, size, value))
    dummy_log.write("%s;W;0x%x;%u;0x%x\n" %("IO_unk3", offset, size, value))
    dummy_log.flush()
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
    dummy_log.flush()
    return 0

def unk4_write(mu, offset, size, value: int, user_data):
    #print("Unk4 write at 0x%x, data size = %u, data value = 0x%x" %(offset, size, value))
    dummy_log.write("%s;W;0x%x;%u;0x%x\n" %("IO_unk4", offset, size, value))
    dummy_log.flush()
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
    dummy_log.flush()
    return 0

def unk8_write(mu, offset, size, value: int, user_data):
    #print("Unk8 write at 0x%x, data size = %u, data value = 0x%x" %(offset, size, value))
    dummy_log.write("%s;W;0x%x;%u;0x%x\n" %("IO_unk8", offset, size, value))
    dummy_log.flush()
    return

mu.mmio_map(IO_UNK8_ADDR, IO_UNK8_LENGHT, unk8_read, None, unk8_write, None)

# hook dummy unk IO_UNKF0071_ADDR
def unkf0071_read(mu, offset, size, user_data) -> int:
    #print("Unkf0071 read at 0x%x, data size = %u" %(offset, size))
    if offset == 0x2:
        return 0x20
    dummy_log.write("%s;R;0x%x;%u\n" %("IO_unkf0071", offset, size))
    dummy_log.flush()
    return 0

def unkf0071_write(mu, offset, size, value: int, user_data):
    #print("Unkf0071 write at 0x%x, data size = %u, data value = 0x%x" %(offset, size, value))
    dummy_log.write("%s;W;0x%x;%u;0x%x\n" %("IO_unkf0071", offset, size, value))
    dummy_log.flush()
    return

mu.mmio_map(IO_UNKF0071_ADDR, IO_UNKF0071_LENGHT, unkf0071_read, None, unkf0071_write, None)

# load roms
#load_mem_file(mu, ROM1_ADDR, ROM_LENGHT, 'roms/rom1.bin')
load_mem_file(mu, 0x40007bc0, ROM_LENGHT, 'roms/rom1.bin', 0x110000, True)
load_mem_file(mu, ROM1_REMAP_ADDR, ROM_LENGHT, 'roms/rom1.bin')
load_mem_file(mu, ROM2_ADDR, ROM_LENGHT, 'roms/rom2.bin')


def hook_block(uc, address, size, user_data):
    blocks_log.write("0x%x\n" %address)
    blocks_log.flush()

#mu.hook_add(UC_HOOK_BLOCK, hook_block)

def hook_code(uc, address, size, user_data):
    
    # print values of registers
    print(">>> CPU context")
    for reg in range(UC_ARM_REG_R0, UC_ARM_REG_R12 + 1):
        rnum = reg - UC_ARM_REG_R0
        print(">>> R%d = 0x%x" %(rnum, mu.reg_read(reg)))

#mu.hook_add(UC_HOOK_CODE, hook_code)

# hook CPU exception
def hook_exception(mu, intno, data):
    print(">>> Exception: %d" %intno)
    print(">>> PC = 0x%x" %mu.reg_read(UC_ARM_REG_PC))

    # skip instruction
    mu.reg_write(UC_ARM_REG_PC, mu.reg_read(UC_ARM_REG_PC) + 4)
    #udbserver(mu, 1234, 0)
    return True

mu.hook_add(UC_HOOK_INTR, hook_exception)

# TODO: Jiffies or it will be stuck at calibrate_delay
# start emulation
try:
    udbserver(mu, 1234, 0)
    mu.emu_start(0x40007bc0, 0x42000000)#, UC_SECOND_SCALE * 120)
except UcError as e:
    print("ERROR: %s" % e)
    # print pc
    print(">>> PC = 0x%x" %mu.reg_read(UC_ARM_REG_PC))


# dump ram
dump_mem_file(mu, RAM_ADDR, RAM_LENGHT, 'out/ram.bin')
dump_mem_file(mu, UNKRAM_ADDR, UNKRAM_LENGHT, 'out/unkram.bin')

blocks_log.close()