
#include "qemu/osdep.h"
#include "qemu/log.h"
#include "qemu/module.h"
#include "hw/registerfields.h"
#include "hw/ssi/soc09s_sflu.h"
#include "hw/irq.h"
#include "hw/qdev-properties.h"
#include "hw/qdev-properties-system.h"
#include "migration/vmstate.h"
#include "trace.h"

REG32(STATE, 0x0)
    FIELD(STATE, BUSY, 0, 1)
REG32(CTRL0, 0x2)
REG32(CTRL1, 0x4)
    FIELD(CTRL1, XCE_CHIP_0, 0, 1)
    FIELD(CTRL1, XCE_CHIP_1, 8, 1)
REG32(CTRL2, 0x6)
    FIELD(CTRL2, XCE_CHIP_2, 0, 1)
    FIELD(CTRL2, XCE_CHIP_3, 8, 1)
REG32(TRIGGER0, 0x8)
REG32(TRIGGER1, 0xA)
REG32(PORT_CTRL, 0x10)
REG32(BUSY_EXT, 0x20)
REG32(SDR_WSIZE0, 0x30)
REG32(SDR_WSIZE1, 0x32)
REG32(SDR_ADDR0, 0x34)
REG32(SDR_ADDR1, 0x36)
REG32(SI_BUFF, 0x50)
REG32(SO_BUFF0, 0x60)
REG32(SO_BUFF1, 0x62)
REG32(SO_BUFF2, 0x64)
REG32(SO_BUFF3, 0x66)
REG32(CTRL, 0x102)
