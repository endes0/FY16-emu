
class DcacheInvPrintingBreakpoint(gdb.Breakpoint):
    def stop(self):
        top = gdb.newest_frame()
        print("Invalidating D-cache: 0x%x len 0x%x" % (top.read_register('r0'), top.read_register('r0')))

class TkernelProgPrintingBreakpoint(gdb.Breakpoint):
    def stop(self):
        top = gdb.newest_frame()
        print("tkernel progress {:x}" % (top.read_register('r0')))

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
InjectRamdumpBreakpoint("*0x11944")

gdb.execute("continue")