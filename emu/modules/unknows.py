from ..utils import dummy_log

# hook dummy unk4
def unk4_read(mu, offset, size, user_data) -> int:
    #print("Unk4 read at 0x%x, data size = %u" %(offset, size))
    if offset == 0x0:
        return 0x200
    elif offset == 0x10:
        return 0
    dummy_log("IO_unk4", offset, size)
    return 0

def unk4_write(mu, offset, size, value: int, user_data):
    #print("Unk4 write at 0x%x, data size = %u, data value = 0x%x" %(offset, size, value))
    dummy_log("IO_unk4", offset, size, False, value)
    return

# hook dummy unk8
def unk8_read(mu, offset, size, user_data) -> int:
    #print("Unk8 read at 0x%x, data size = %u" %(offset, size))
    if offset == 0x800: 
        return 0x2
    elif offset == 0x720:
        return 0x40
    dummy_log("IO_unk8", offset, size)
    return 0

def unk8_write(mu, offset, size, value: int, user_data):
    #print("Unk8 write at 0x%x, data size = %u, data value = 0x%x" %(offset, size, value))
    dummy_log("IO_unk8", offset, size, False, value)
    return

# hook dummy unk IO_UNKF0071_ADDR
def unkf0071_read(mu, offset, size, user_data) -> int:
    #print("Unkf0071 read at 0x%x, data size = %u" %(offset, size))
    if offset == 0x2:
        return 0x20
    dummy_log("IO_unkf0071", offset, size)
    return 0

def unkf0071_write(mu, offset, size, value: int, user_data):
    #print("Unkf0071 write at 0x%x, data size = %u, data value = 0x%x" %(offset, size, value))
    dummy_log("IO_unkf0071", offset, size, False, value)
    return

# hook dummy unk3
def unk3_read(mu, offset, size, user_data) -> int:
    #print("Unk3 read at 0x%x, data size = %u" %(offset, size))
    if offset == 0x21:
        return 0x8
    if offset == 0x72:
        return 0x10
    dummy_log("IO_unk3", offset, size)
    return 0

def unk3_write(mu, offset, size, value: int, user_data):
    #print("Unk3 write at 0x%x, data size = %u, data value = 0x%x" %(offset, size, value))
    dummy_log("IO_unk3", offset, size, False, value)
    return
