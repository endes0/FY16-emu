import os


def decode_entry(e: bytes, va: int, continuos: bool) -> bool:
    old_continuos = continuos
    continuos = False

    # check 0:1 bits
    e_type = e[0] & 0x3

    if e_type == 0:
        print("0x%08x: Fault" % (va))
    elif e_type == 1:
        print("0x%08x: Coarse page table" % (va))
    elif e_type == 2:
        # baddr 31:20
        baddr = e[3] << 24 | ((e[2] & 0xf0) << 16)
        # tex 14:12
        tex = e[1] >> 4
        # ap 11:10
        ap = (e[1] >> 2) & 0x3
        # domain 8:5
        domain = e[0] >> 5
        #CB 3:2
        cb = (e[0] >> 2) & 0x3
        #S 16
        s = e[2] & 0x1
        # nG 17
        ng = (e[2] >> 1) & 0x1
        # xN 4
        xn = (e[0] >> 4) & 0x1
        if ap > 0:
            continuos = True
            if continuos != old_continuos:
                print("")
            print("0x%08x: Section to 0x%08x. TEX: 0x%x AP: 0x%x Domain: 0x%x CB: 0x%x S: %d nG: %d xN: %d" % (va, baddr, tex, ap, domain, cb, s, ng, xn))
        #print(e)
    elif e_type == 3:
        print("0x%08x: undef" % (va))
    
    return continuos


#FILE = 'out/ram.bin'
FILE = 'roms/rom1.bin'
#POS = 0x5400000
#POS = 0x1918
POS = 0x10b000
with open(FILE, 'rb') as f:
    continuos = True
    f.seek(POS)

    for i in range(int(16 * (1024)/4)): # 1KB
        # read 4 bytes little endian
        data = f.read(4)
        # convert to big endian
        #data = data[::-1]

        continuos = decode_entry(data, i << 20, continuos)