
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
REG32(CTRL1, 0x4)
    FIELD(CTRL1, XCE_CHIP_0, 0, 1)
    FIELD(CTRL1, XCE_CHIP_1, 8, 1)
REG32(CTRL2, 0x6)
    FIELD(CTRL2, XCE_CHIP_2, 0, 1)
    FIELD(CTRL2, XCE_CHIP_3, 8, 1)


static void deassert_all_cs(Soc09sSflu *s) {
    for (size_t i = 0; i < 4; i++)
    {
        qemu_irq_raise(s->cs_lines[i]);
    }
    
}

static void sflu_xfer(Soc09sSflu *s) {
    while (!fifo8_is_empty(&s->tx_fifo) && !fifo8_is_full(&s->rx_fifo)) {
        uint8_t val = fifo8_pop(&s->tx_fifo);
        fifo8_push(&s->rx_fifo, val);
    }
}

static uint64_t sflu_read(void *opaque, hwaddr addr, unsigned size)
{
    Soc09sSflu *s = opaque;
    switch (addr) {
    case SFLU_STATE:
        return FIELD_DP32(0, STATE, BUSY, 0);
        break;
    case SFLU_CTRL1:
        return FIELD_DP32(0, CTRL1, XCE_CHIP_0, s->selected_chip == 0);
        return FIELD_DP32(0, CTRL1, XCE_CHIP_1, s->selected_chip == 1);
        break;
    case SFLU_CTRL2:
        return FIELD_DP32(0, CTRL2, XCE_CHIP_2, s->selected_chip == 2);
        return FIELD_DP32(0, CTRL2, XCE_CHIP_3, s->selected_chip == 3);
        break;
    case SFLU_SO_BUFF1:
        return fifo8_pop(&s->rx_fifo);
        break;
    default:
        printf("sflu: unhandled read from 0x%"HWADDR_PRIx"\n", addr);
        return 0;
        break;
    }
}

static void sflu_write(void *opaque, hwaddr addr, uint64_t val, unsigned size)
{
    Soc09sSflu *s = opaque;
    
    switch (addr) {
    case SFLU_CTRL1:
        sflu_xfer(s);

        if (FIELD_EX32(val, CTRL1, XCE_CHIP_0)) {
            s->selected_chip = 0;
            deassert_all_cs(s);
            qemu_irq_lower(s->cs_lines[0]);
        } else if (FIELD_EX32(val, CTRL1, XCE_CHIP_1)) {
            s->selected_chip = 1;
            deassert_all_cs(s);
            qemu_irq_lower(s->cs_lines[1]);
        }
        break;
    case SFLU_CTRL2:
        sflu_xfer(s);
        
        if (FIELD_EX32(val, CTRL2, XCE_CHIP_2)) {
            s->selected_chip = 2;
            deassert_all_cs(s);
            qemu_irq_lower(s->cs_lines[2]);
        } else if (FIELD_EX32(val, CTRL2, XCE_CHIP_3)) {
            s->selected_chip = 3;
            deassert_all_cs(s);
            qemu_irq_lower(s->cs_lines[3]);
        }
        break;
    case SFLU_SI_BUFF:
        if (!fifo8_is_full(&s->tx_fifo)) {
            fifo8_push(&s->tx_fifo, val);
        } else {
            printf("sflu: tx fifo full\n");
            //TODO: set busy bit
        }
        
        break;
    default:
        printf("sflu: unhandled write to 0x%"HWADDR_PRIx"\n", addr);
        break;
    }
}

static const MemoryRegionOps sflu_ops = {
    .read = sflu_read,
    .write = sflu_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
};

static void soc09s_sflu_realize(DeviceState *dev, Error **errp)
{
    SysBusDevice *sbd = SYS_BUS_DEVICE(dev);
    Soc09sSflu *s = SOC09S_SFLU(dev);

    memory_region_init_io(&s->mmio, OBJECT(s), &sflu_ops, s, "sflu", 0x1000);
    sysbus_init_mmio(sbd, &s->mmio);
    //sysbus_init_irq(sbd, &s->irq);
    s->ssi = ssi_create_bus(dev, "ssi");

    qdev_init_gpio_out_named(dev, s->cs_lines, "cs", 4);

    fifo8_create(&s->rx_fifo, 256);
    fifo8_create(&s->tx_fifo, 256);
}

static void soc09s_sflu_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    //dc->reset = soc09s_sflu_reset;
    dc->realize = soc09s_sflu_realize;
}

static const TypeInfo soc09s_sflu_info = {
    .name          = TYPE_SOC09S_SFLU,
    .parent        = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(Soc09sSflu),
    .class_init    = soc09s_sflu_class_init,
};

static void soc09s_sflu_register_types(void)
{
    type_register_static(&soc09s_sflu_info);
}

type_init(soc09s_sflu_register_types)
