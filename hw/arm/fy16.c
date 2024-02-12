
#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu/module.h"
#include "hw/qdev-core.h"
#include "hw/sysbus.h"
#include "hw/misc/unimp.h"
#include "hw/qdev-properties.h"
#include "hw/loader.h"
#include "sysemu/blockdev.h"
#include "sysemu/sysemu.h"
#include "sysemu/block-backend.h"
#include "hw/arm/fy16.h"

/* Memory map */
const hwaddr fy16_memmap[] = {
    [ROM1] = 0x00000000,       [ROM2] = 0x04000000,
    [ROM1_REMAP] = 0x20000000, [ROM2_REMAP] = 0x24000000,
    [RAM] = 0x40000000,        [RAM_REMAP1] = 0x50000000,
    [RAM_REMAP2] = 0x60000000, [RAM_REMAP3] = 0x70000000,
    [GOBI] = 0xD0000000,       [ETH] = 0xD0400000,
    [EHCI_HOST] = 0xD0802000,  [UNK5] = 0xE0001000,
    [UNK9] = 0xE0003000,       [EHCI] = 0xE0800000,
    [ASIC_SYSCU] = 0xE0812000, [SERIAL1] = 0xE0816000,
    [SERIAL2] = 0xE0817000,    [SERIAL3] = 0xE0818000,
    [UNK6] = 0xE0819000,       [UNK7] = 0xE081A000,
    [MSG_RAM] = 0xE0C00000,    [ASICIOU] = 0xF0000000,
    [UNKF0071] = 0xF0071000,   [IDC] = 0xF0080000,
    [UNK4] = 0xF0081000,       [UNK8] = 0xF0084000,
    [SFLU3] = 0xF0088000,      [SPIU] = 0xF0089000,
    [FLASH_BASE] = 0xF4000000,
};

/* List of unimplemented devices */
struct Fy16Unimplemented {
  const char *device_name;
  hwaddr base;
  hwaddr size;
} fy16_unimplemented[] = {{"GOBI", fy16_memmap[GOBI], 0x400000},
                          {"ETHERNET", fy16_memmap[ETH], 0x2000},
                          {"EHCI_HOST", fy16_memmap[EHCI_HOST], 0x1000},
                          {"UNK9", fy16_memmap[UNK9], 0x1000},
                          {"EHCI", fy16_memmap[EHCI], 0x2000},
                          {"ASIC_SYSCU", fy16_memmap[ASIC_SYSCU], 0x2000},
                          {"UNK6", fy16_memmap[UNK6], 0x1000},
                          {"UNK7", fy16_memmap[UNK7], 0x1000},
                          {"IDC", fy16_memmap[IDC], 0x1000},
                          {"SPIU", fy16_memmap[SPIU], 0x1000},
                          {"FLASH_BASE", fy16_memmap[FLASH_BASE], 0x1000000}};

/* ASICIOU */

static void fy16_asiociou_write(void *opaque, hwaddr addr, uint64_t val,
                                unsigned size) {
  //Fy16State *s = opaque;
  printf("fy16_asiociou_write: addr=0x%" HWADDR_PRIx " val=0x%" PRIx64
         " size=%u\n",
         addr, val, size);
}

static uint64_t fy16_asiociou_read(void *opaque, hwaddr addr, unsigned size) {
  //Fy16State *s = opaque;
  printf("fy16_asiociou_read: addr=0x%" HWADDR_PRIx " size=%u\n", addr, size);
  return 0;
}

static const MemoryRegionOps fy16_asiociou_ops = {
    .read = fy16_asiociou_read, .write = fy16_asiociou_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
};


static void fy16_connect_flash(Fy16State *s, int cs_no,
                                  const char *flash_type, DriveInfo *dinfo)
{
    DeviceState *flash;
    qemu_irq flash_cs;

    flash = qdev_new(flash_type);
    if (dinfo) {
        qdev_prop_set_drive(flash, "drive", blk_by_legacy_dinfo(dinfo));
    }
    qdev_realize_and_unref(flash, BUS(s->sflu.ssi), &error_fatal);

    flash_cs = qdev_get_gpio_in_named(flash, SSI_GPIO_CS, 0);
    qdev_connect_gpio_out_named(DEVICE(&s->sflu), "cs", cs_no, flash_cs);
}


static void fy16_init(Object *obj) {
  Fy16State *s = FY16(obj);
  // int i;

  object_initialize_child(obj, "cpu", &s->cpu, ARM_CPU_TYPE_NAME("arm1176"));

  object_initialize_child(obj, "sflu", &s->sflu, TYPE_SOC09S_SFLU);

  // object_initialize_child(obj, "uart", &s->uart, TYPE_DIGIC_UART);
  //object_initialize_child(obj, "serial0", &s->serial0, TYPE_SH_SERIAL);
}

static void fy16_realize(DeviceState *dev, Error **errp) {
  Fy16State *s = FY16(dev);
  // SysBusDevice *sbd;
  // int i;

  if (!object_property_set_bool(OBJECT(&s->cpu), "reset-hivecs", false, errp)) {
    return;
  }

  if (!qdev_realize(DEVICE(&s->cpu), NULL, errp)) {
    return;
  }

  /* ROMS */
  memory_region_init_rom(&s->rom1, OBJECT(dev), "rom1", 0x4000000, errp);
  memory_region_add_subregion(get_system_memory(), fy16_memmap[ROM1], &s->rom1);

  memory_region_init_rom(&s->rom2, OBJECT(dev), "rom2", 0x4000000, errp);
  memory_region_add_subregion(get_system_memory(), fy16_memmap[ROM2], &s->rom2);

  /* ROMS ALIASES */
  memory_region_init_alias(&s->rom1_remap, OBJECT(dev), "rom1_remap",
                           get_system_memory(), fy16_memmap[ROM1], 0x800000);
  memory_region_add_subregion(get_system_memory(), fy16_memmap[ROM1_REMAP],
                              &s->rom1_remap);

  memory_region_init_alias(&s->rom2_remap, OBJECT(dev), "rom2_remap",
                           get_system_memory(), fy16_memmap[ROM2], 0x800000);
  memory_region_add_subregion(get_system_memory(), fy16_memmap[ROM2_REMAP],
                              &s->rom2_remap);

  /* RAM ALIASES */
  memory_region_init_alias(&s->ram_remap1, OBJECT(dev), "ram_remap1",
                           get_system_memory(), fy16_memmap[RAM], 0x1000000);
  memory_region_add_subregion(get_system_memory(), fy16_memmap[RAM_REMAP1],
                              &s->ram_remap1);

  memory_region_init_alias(&s->ram_remap2, OBJECT(dev), "ram_remap2",
                           get_system_memory(), fy16_memmap[RAM], 0x1000000);
  memory_region_add_subregion(get_system_memory(), fy16_memmap[RAM_REMAP2],
                              &s->ram_remap2);

  memory_region_init_alias(&s->ram_remap3, OBJECT(dev), "ram_remap3",
                           get_system_memory(), fy16_memmap[RAM], 0x1000000);
  memory_region_add_subregion(get_system_memory(), fy16_memmap[RAM_REMAP3],
                              &s->ram_remap3);

  /* MSG_RAM */
  memory_region_init_ram(&s->msg_ram, OBJECT(dev), "msg_ram", 0x4000, errp);
  memory_region_add_subregion(get_system_memory(), fy16_memmap[MSG_RAM],
                              &s->msg_ram);

  /* SERIAL 0 */
  DeviceState *serial0 = qdev_new(TYPE_SH_SERIAL);
  serial0->id = g_strdup("serial0");
  qdev_prop_set_chr(serial0, "chardev", serial_hd(0));
  qdev_prop_set_uint8(serial0, "features", SH_SERIAL_FEAT_SCIF);
  if (!sysbus_realize_and_unref(SYS_BUS_DEVICE(serial0), errp)) {
    return;
  }
  sysbus_mmio_map(SYS_BUS_DEVICE(serial0), 0, fy16_memmap[SERIAL1]);

  /* ASICIOU */
  memory_region_init_io(&s->asiociou, OBJECT(dev), &fy16_asiociou_ops, s,
                        "asiociou", 0x1000);
  memory_region_add_subregion(get_system_memory(), fy16_memmap[ASICIOU],
                              &s->asiociou);

  /* SFLU */
  if (!sysbus_realize(SYS_BUS_DEVICE(&s->sflu), errp)) {
    return;
  }
  sysbus_mmio_map(SYS_BUS_DEVICE(&s->sflu), 0, fy16_memmap[SFLU3]);

  /* connect W25Q to the sflu */
  //TODO: direct memory map support (ROM0)
  //TODO: load rom dump
  fy16_connect_flash(s, 0, "w25q64", NULL);


  /* Unimplemented devices */
  for (int i = 0; i < ARRAY_SIZE(fy16_unimplemented); i++) {
    create_unimplemented_device(fy16_unimplemented[i].device_name,
                                    fy16_unimplemented[i].base,
                                    fy16_unimplemented[i].size);
  }
}

static void fy16_class_init(ObjectClass *oc, void *data) {
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

static void fy16_register_types(void) { type_register_static(&fy16_type_info); }

type_init(fy16_register_types)