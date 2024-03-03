
class DcacheInvPrintingBreakpoint(gdb.Breakpoint):
    def stop(self):
        top = gdb.newest_frame()
        print("Invalidating D-cache: 0x%x len 0x%x" % (top.read_register('r0'), top.read_register('r0')))

class TkernelProgPrintingBreakpoint(gdb.Breakpoint):
    def stop(self):
        top = gdb.newest_frame()
        print("tkernel progress 0x%x" % (top.read_register('r0')))

class DebugPrintPrintingBreakpoint(gdb.Breakpoint):
    def stop(self):
        top = gdb.newest_frame()
        inf = gdb.inferiors()[0]
        current_addr = top.read_register('r0')
        c = inf.read_memory(top.read_register('r0'), 1).tobytes()
        while c != b'\0':
            print(c.decode('utf-8'), end='')
            current_addr += 1
            c = inf.read_memory(current_addr, 1).tobytes()

class RegisterIntPrintingBreakpoint(gdb.Breakpoint):
    def stop(self):
        top = gdb.newest_frame()
        print("Register_int 0x%x 0x%x" % (top.read_register('r0'), top.read_register('r1')))

class InjectRamdumpBreakpoint(gdb.Breakpoint):
    def stop(self):
        top = gdb.newest_frame()
        print("Injecting RAM dumps")
        gdb.execute("restore roms/fy16/dump_1.bin binary 0x45100000")
        gdb.execute("restore roms/fy16/dump_2.bin binary 0x45b00000")
        #inject_file(0x45100000, "roms/fy16/dump_1.bin")
        #inject_file(0x45b00000, "roms/fy16/dump_2.bin")
        print("RAM dumps injected")

#gdb.execute("start")

DcacheInvPrintingBreakpoint("*0x15d64")
TkernelProgPrintingBreakpoint("*0x45e26b84")
RegisterIntPrintingBreakpoint("*0x45e00c50")
DebugPrintPrintingBreakpoint("*0x45490428")
DebugPrintPrintingBreakpoint("*0x45e0c92c")
InjectRamdumpBreakpoint("*0x11944")

gdb.execute("continue")