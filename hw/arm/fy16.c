
#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu/module.h"
#include "hw/arm/fy16.h"
#include "hw/qdev-properties.h"
#include "sysemu/sysemu.h"

/* Memory map */
const hwaddr fy16_memmap[] = {
    [ROM1]              = 0x00000000,
    [ROM2]              = 0x04000000,
    [ROM1_REMAP]        = 0x20000000,
    [ROM2_REMAP]        = 0x24000000,
    [RAM]               = 0x40000000,
    [RAM_REMAP1]        = 0x50000000,
    [RAM_REMAP2]        = 0x60000000,
    [RAM_REMAP3]        = 0x70000000,
    [GOBI]              = 0xD0000000,
    [ETH]               = 0xD0400000,
    [EHCI_HOST]         = 0xD0802000,
    [UNK5]              = 0xE0001000,
    [UNK9]              = 0xE0003000,
    [EHCI]              = 0xE0800000,
    [ASIC_SYSCU]        = 0xE0812000,
    [SERIAL1]           = 0xE0816000,
    [SERIAL2]           = 0xE0817000,
    [SERIAL3]           = 0xE0818000,
    [UNK6]              = 0xE0819000,
    [UNK7]              = 0xE081A000,
    [MSG_RAM]           = 0xE0C00000,
    [ASICIOU]           = 0xF0000000,
    [UNKF0071]          = 0xF0071000,
    [IDC]               = 0xF0080000,
    [UNK4]              = 0xf0081000,
    [UNK8]              = 0xF0084000,
    [SFLU3]             = 0xF0088000,
    [SPIU]              = 0xF0089000,
    [FLASH_BASE]        = 0xF4000000,
};

/* List of unimplemented devices */
struct Fy16Unimplemented {
    const char *device_name;
    hwaddr base;
    hwaddr size;
} fy16_unimplemented[] = {
    { "GOBI",  fy16_memmap[GOBI], 0x400000 },
    { "ETHERNET", fy16_memmap[ETH], 0x2000 },
    { "EHCI_HOST", fy16_memmap[EHCI_HOST], 0x1000 },
    { "UNK9", fy16_memmap[UNK9], 0x1000 },
    { "EHCI", fy16_memmap[EHCI], 0x2000 },
    { "ASIC_SYSCU", fy16_memmap[ASIC_SYSCU], 0x2000 },
    { "UNK6", fy16_memmap[UNK6], 0x1000 },
    { "UNK7", fy16_memmap[UNK7], 0x1000 },
    { "IDC", fy16_memmap[IDC], 0x1000 },
    { "SPIU", fy16_memmap[SPIU], 0x1000 },
    { "FLASH_BASE", fy16_memmap[FLASH_BASE], 0x1000000 }
};

static void fy16_init(Object *obj)
{
    Fy16State *s = FY16(obj);
    //int i;

    object_initialize_child(obj, "cpu", &s->cpu, ARM_CPU_TYPE_NAME("arm1176"));


    //object_initialize_child(obj, "uart", &s->uart, TYPE_DIGIC_UART);
}

static void fy16_realize(DeviceState *dev, Error **errp)
{
    Fy16State *s = FY16(dev);
    //SysBusDevice *sbd;
    //int i;

    if (!object_property_set_bool(OBJECT(&s->cpu), "reset-hivecs", true,
                                  errp)) {
        return;
    }

    if (!qdev_realize(DEVICE(&s->cpu), NULL, errp)) {
        return;
    }

    /*qdev_prop_set_chr(DEVICE(&s->uart), "chardev", serial_hd(0));
    if (!sysbus_realize(SYS_BUS_DEVICE(&s->uart), errp)) {
        return;
    }

    sbd = SYS_BUS_DEVICE(&s->uart);
    sysbus_mmio_map(sbd, 0, DIGIC_UART_BASE);*/
}

static void fy16_class_init(ObjectClass *oc, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(oc);

    dc->realize = fy16_realize;
    /* Reason: Uses serial_hds in the realize function --> not usable twice */
    dc->user_creatable = false;
}

static const TypeInfo fy16_type_info = {
    .name = TYPE_FY16,
    .parent = TYPE_DEVICE,
    .instance_size = sizeof(Fy16State),
    .instance_init = fy16_init,
    .class_init = fy16_class_init,
};

static void fy16_register_types(void)
{
    type_register_static(&fy16_type_info);
}

type_init(fy16_register_types)