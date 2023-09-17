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