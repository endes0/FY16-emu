#from gdb_plus import *

#dbg = Debugger("roms/fy16/fy16_1.bin").remote('localhost', 1234)

#def funcb_invalidate_dcache(dbg: Debugger):
#    log.info("Invalidating D-cache: 0x%x len 0x%x" % (dbg.registers['r0'], dbg.registers['r1']))
#    return False

#dbg.breakpoint(0x15d64, callback=funcb_invalidate_dcache)

#dbg.cont()

from gdb_remote_client import GdbRemoteClient

# Connect to stub running on localhost, TCP port 3333
cli = GdbRemoteClient("localhost", 1234) 
cli.connect()


REGS_NAMES = ["r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "sp", "lr", "pc", "cpsr"]

def espace_binary_data(data: bytes) -> bytearray:
    result = bytearray()
    for c in data:
        if c in (0x23, 0x24, 0x7d):
            result.append(0x7d)
            result.append(c ^ 0x20)
        else:
            result.append(c)
    return result
            
def write_memory(addr, data: bytes):
    hexstring_len = "{:08x}".format(len(data))
    resp = cli.cmd("M" + addr + "," + hexstring_len + ":" + data.hex())
    if resp != "OK":
        raise RuntimeError("Failed to write memory at address " + addr + ": " + resp)

def inject_file(addr: int, filename: str):
    with open(filename, "rb") as f:
        # transmit chunks of 1024 bytes
        while True:
            chunk = f.read(1024)
            if len(chunk) == 0:
                break
            hexstring_addr = "{:08x}".format(addr)
            write_memory(hexstring_addr, chunk)
            addr += len(chunk)

def get_gpr():
    resp = cli.cmd("g")
    
    # split resp every 8 characters
    regs = [resp[i:i+8] for i in range(0, len(resp), 8)]

    # reverse endianness of each register
    regs = [reg[6:8] + reg[4:6] + reg[2:4] + reg[0:2] for reg in regs]

    # convert to int
    regs = [int(reg, 16) for reg in regs]

    # create a dictionary
    return dict(zip(REGS_NAMES, regs))

def restore_breakpoint(addr):
        resp = cli.cmd("z0," + addr + ",0")
        if resp != "OK":
            raise RuntimeError("Failed to disable breakpoint at address 0x%x: " % addr + resp)
        resp = cli.cmd("s")
        resp = cli.cmd("Z0," + addr + ",0")
        if resp != "OK":
            raise RuntimeError("Failed to restore breakpoint at address 0x%x: " % addr + resp)

# Example how to interact with the stub:

# cli.cmd("...") sends a command and returns the response
resp = cli.cmd("qSupported")
print("The remote stub supports these features: " + resp)  

resp = cli.cmd("g")
print("Values of general-purpose registers: " + resp)

resp = cli.cmd("vMustReplyEmpty")
if resp != "":
    raise RuntimeError("Unexpected reply to command vMustReplyEmpty")


resp = cli.cmd("Z0,15d64,0")
print("Set a breakpoint at address 0x15d64: " + resp)
resp = cli.cmd("Z0,11944,0")
print("Set a breakpoint at address 0x11944: " + resp)

#write_memory("45100000", b'\xaa\x00\x00\x00\xaa\x00\x00\x00')

while True:
    resp = cli.cmd("c")
    print("Stopped by: " + resp)
    regs = get_gpr()
    if regs["pc"] == 0x15d64:
        print("Invalidating D-cache: 0x%x len 0x%x" % (regs['r0'], regs['r1']))
        restore_breakpoint("15d64")
    elif regs["pc"] == 0x11944:
        print("Injecting RAM dumps")
        inject_file(0x45100000, "roms/fy16/dump_1.bin")
        inject_file(0x45b00000, "roms/fy16/dump_2.bin")
        print("RAM dumps injected")
        restore_breakpoint("11944")
        



# Finally, disconnect
cli.disconnect()