
#ifndef SOC09S_SFLU_H
#define SOC09S_SFLU_H

#include "hw/sysbus.h"
#include "hw/ssi/ssi.h"
#include "qemu/fifo8.h"
#include "qom/object.h"

#define TYPE_SOC09S_SFLU "soc09s-sflu"
OBJECT_DECLARE_SIMPLE_TYPE(Soc09sSflu, SOC09S_SFLU)

#define SFLU_STATE 0x00
#define SFLU_CTRL0 0x02
#define SFLU_CTRL1 0x04
#define SFLU_CTRL2 0x06
#define SFLU_TRIGGER0 0x08
#define SFLU_TRIGGER1 0x0A
#define SFLU_PORT_CTRL 0x10
#define SFLU_BUSY_EXT 0x20
#define SFLU_SDR_WSIZE0 0x30
#define SFLU_SDR_WSIZE1 0x32
#define SFLU_SDR_ADDR0 0x34
#define SFLU_SDR_ADDR1 0x36
#define SFLU_SI_BUFF 0x50
#define SFLU_SO_BUFF0 0x60
#define SFLU_SO_BUFF1 0x62
#define SFLU_SO_BUFF2 0x64
#define SFLU_SO_BUFF3 0x66
#define SFLU_CTRL 0x102

typedef struct Soc09sSflu {
    /* <private> */
    SysBusDevice parent_obj;
    uint16_t selected_chip;

    /* <public> */
    Fifo8 rx_fifo;
    Fifo8 tx_fifo;
    MemoryRegion mmio;
    SSIBus *ssi;
    qemu_irq cs_lines[4];
} Soc09sSflu;

#endif // SOC09S_SFLU_H