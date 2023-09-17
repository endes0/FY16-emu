dummy_log_f = open('out/dummy.log', 'w')

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

def dummy_log(name, offset, size, is_read = True, value = None):
    if is_read:
        dummy_log_f.write("%s;R;0x%x;%u\n" %(name, offset, size))
    else:
        dummy_log_f.write("%s;W;0x%x;%u;0x%x\n" %(name, offset, size, value))
    dummy_log_f.flush()

def dummy_map(uc, name, addr, lenght):
    def dummy_read(mu, offset, size, user_data) -> int:
        dummy_log(name, offset, size)
        return 0
    
    def dummy_write(mu, offset, size, value: int, user_data):
        dummy_log(name, offset, size, False, value)
        return

    uc.mmio_map(addr, lenght, dummy_read, None, dummy_write, None)

def mirror_map(uc, addr, lenght, mirror_addr):
    def mirror_read(mu, offset, size, user_data) -> int:
        return int.from_bytes(mu.mem_read(mirror_addr + offset, size), byteorder='little', signed=False)

    def mirror_write(mu, offset, size, value: int, user_data):
        mu.mem_write(mirror_addr + offset, value.to_bytes(size, byteorder='little', signed=False))

    uc.mmio_map(addr, lenght, mirror_read, None, mirror_write, None)

def patch_nop(mu, addr):
    mu.mem_write(addr, b'\x00\xf0\x20\xe3')