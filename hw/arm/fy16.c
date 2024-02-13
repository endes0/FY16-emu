
#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu/module.h"
#include "cpu.h"
#include "hw/qdev-core.h"
#include "hw/sysbus.h"
#include "hw/misc/unimp.h"
#include "hw/qdev-properties.h"
#include "hw/loader.h"
#include "sysemu/blockdev.h"
#include "sysemu/sysemu.h"
#include "sysemu/block-backend.h"
#include "target/arm/cpregs.h"
#include "hw/arm/fy16.h"

/* Memory map */
const hwaddr fy16_memmap[] = {
    [ROM1] = 0x00000000,
    [ROM2] = 0x04000000,
    [ROM1_REMAP] = 0x20000000,
    [ROM2_REMAP] = 0x24000000,
    [RAM] = 0x40000000,
    [RAM_REMAP1] = 0x50000000,
    [RAM_REMAP2] = 0x60000000,
    [RAM_REMAP3] = 0x70000000,
    [GOBI] = 0xD0000000,
    [ETH] = 0xD0400000,
    [EHCI_HOST] = 0xD0802000,
    [UNK5] = 0xE0001000,
    [UNK9] = 0xE0003000,
    [EHCI] = 0xE0800000,
    [ASIC_SYSCU] = 0xE0812000,
    [SERIAL1] = 0xE0816000,
    [SERIAL2] = 0xE0817000,
    [SERIAL3] = 0xE0818000,
    [UNK6] = 0xE0819000,
    [UNK7] = 0xE081A000,
    [MSG_RAM] = 0xE0C00000,
    [ASICIOU] = 0xF0000000,
    [UNK10] = 0xF0005000,
    [UNK11] = 0xF0050000,
    [UNKF0054] = 0xF0054000,
    [UNK12] = 0xF0059000,
    [UNK13] = 0xF0060000,
    [UNKF0070] = 0xF0070000,
    [UNKF0071] = 0xF0071000,
    [IDC] = 0xF0080000,
    [UNK4] = 0xF0081000,
    [UNK8] = 0xF0084000,
    [SFLU3] = 0xF0088000,
    [SPIU] = 0xF0089000,
    [UNK14] = 0xF008B000,
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
                          {"EHCI", fy16_memmap[EHCI], 0x2000},
                          {"ASIC_SYSCU", fy16_memmap[ASIC_SYSCU], 0x2000},
                          {"UNK6", fy16_memmap[UNK6], 0x1000},
                          {"UNK7", fy16_memmap[UNK7], 0x1000},
                          {"UNK10", fy16_memmap[UNK10], 0x1000},
                          {"UNK11", fy16_memmap[UNK11], 0x1000},
                          {"UNKF0054", fy16_memmap[UNKF0054], 0x1000},
                          {"UNK12", fy16_memmap[UNK12], 0x1000},
                          {"UNK13", fy16_memmap[UNK13], 0x10000},
                          {"UNKF0070", fy16_memmap[UNKF0070], 0x1000},
                          {"IDC", fy16_memmap[IDC], 0x1000},
                          {"SPIU", fy16_memmap[SPIU], 0x1000},
                          {"UNK14", fy16_memmap[UNK14], 0x1000},
                          {"FLASH_BASE", fy16_memmap[FLASH_BASE], 0x1000000}};

/* TCM */

static uint64_t arm_cp15_dtcmrr_read(CPUARMState *env, const ARMCPRegInfo *ri) {
  //TODO: https://developer.arm.com/documentation/ddi0301/h/system-control-coprocessor/system-control-processor-registers/c9--data-tcm-region-register
  return 0x8000800d;
}

static uint64_t arm_cp15_itcmrr_read(CPUARMState *env, const ARMCPRegInfo *ri) {
  //TODO: https://developer.arm.com/documentation/ddi0301/h/system-control-coprocessor/system-control-processor-registers/c9--instruction-tcm-region-register
  return 0x80000019;
}

static void arm_cp15_dtcmrr_write(CPUARMState *env, const ARMCPRegInfo *ri,
                                      uint64_t value) {
  printf("arm_cp15_dtcmrr_write: value=0x%" PRIx64 "\n", value);
}

static void arm_cp15_itcmrr_write(CPUARMState *env, const ARMCPRegInfo *ri,
                                      uint64_t value) {
  printf("arm_cp15_itcmrr_write: value=0x%" PRIx64 "\n", value);
}

static const ARMCPRegInfo fy16_tcm_cp_reginfo[] = {
    { .name = "DTCMRR", .cp = 15, .crn = 9, .crm = 1,
      .opc1 = 0, .opc2 = 0, .access = PL1_RW, .resetvalue = 0x0,
      .readfn = arm_cp15_dtcmrr_read, .writefn = arm_cp15_dtcmrr_write},
    { .name = "ITCMRR", .cp = 15, .crn = 9, .crm = 1,
      .opc1 = 0, .opc2 = 1, .access = PL1_RW, .resetvalue = 0x0,
      .readfn = arm_cp15_itcmrr_read, .writefn = arm_cp15_itcmrr_write},
};


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

  switch (addr)
  {
  case 0x21:
    return 0x8;
    break;
  
  case 0x72:
    return 0x10;
    break;
  
  default:
    printf("fy16_asiociou_read: addr=0x%" HWADDR_PRIx " size=%u\n", addr, size);
    return 0;
    break;
  }
}

static const MemoryRegionOps fy16_asiociou_ops = {
    .read = fy16_asiociou_read, .write = fy16_asiociou_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
};


/* UNK4 */

static void fy16_unk4_write(void *opaque, hwaddr addr, uint64_t val,
                                unsigned size) {
  //Fy16State *s = opaque;
  printf("fy16_unk4_write: addr=0x%" HWADDR_PRIx " val=0x%" PRIx64
         " size=%u\n",
         addr, val, size);
}

static uint64_t fy16_unk4_read(void *opaque, hwaddr addr, unsigned size) {
  //Fy16State *s = opaque;

  switch (addr)
  {
  case 0x0:
    return 0x200;
    break;
  
  default:
    printf("fy16_unk4_read: addr=0x%" HWADDR_PRIx " size=%u\n", addr, size);
    return 0;
    break;
  }
}

static const MemoryRegionOps fy16_unk4_ops = {
    .read = fy16_unk4_read, .write = fy16_unk4_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
};


/* UNK5 */

static void fy16_unk5_write(void *opaque, hwaddr addr, uint64_t val,
                                unsigned size) {
  //Fy16State *s = opaque;
  printf("fy16_unk5_write: addr=0x%" HWADDR_PRIx " val=0x%" PRIx64
         " size=%u\n",
         addr, val, size);
}

static uint64_t fy16_unk5_read(void *opaque, hwaddr addr, unsigned size) {
  //Fy16State *s = opaque;

  switch (addr)
  {
  case 0x0:
    uint64_t intno = 0x67;
    return (intno - 0x20) << 0x10;
    break;
  
  default:
    printf("fy16_unk5_read: addr=0x%" HWADDR_PRIx " size=%u\n", addr, size);
    return 0;
    break;
  }
}

static const MemoryRegionOps fy16_unk5_ops = {
    .read = fy16_unk5_read, .write = fy16_unk5_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
};


/* UNK8 */

static void fy16_unk8_write(void *opaque, hwaddr addr, uint64_t val,
                                unsigned size) {
  //Fy16State *s = opaque;
  printf("fy16_unk8_write: addr=0x%" HWADDR_PRIx " val=0x%" PRIx64
         " size=%u\n",
         addr, val, size);
}

static uint64_t fy16_unk8_read(void *opaque, hwaddr addr, unsigned size) {
  //Fy16State *s = opaque;

  switch (addr)
  {
  case 0x800:
    return 0x2;
    break;

  case 0x720:
    return 0x40;
    break;
  
  default:
    printf("fy16_unk8_read: addr=0x%" HWADDR_PRIx " size=%u\n", addr, size);
    return 0;
    break;
  }
}

static const MemoryRegionOps fy16_unk8_ops = {
    .read = fy16_unk8_read, .write = fy16_unk8_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
};


/* UNKF71 */

static void fy16_unkf71_write(void *opaque, hwaddr addr, uint64_t val,
                                unsigned size) {
  //Fy16State *s = opaque;
  printf("fy16_unkf71_write: addr=0x%" HWADDR_PRIx " val=0x%" PRIx64
         " size=%u\n",
         addr, val, size);
}

static uint64_t fy16_unkf71_read(void *opaque, hwaddr addr, unsigned size) {
  //Fy16State *s = opaque;

  switch (addr)
  {
  case 0x2:
    return 0x20;
    break;
  default:
    printf("fy16_unkf71_read: addr=0x%" HWADDR_PRIx " size=%u\n", addr, size);
    return 0;
    break;
  }
}

static const MemoryRegionOps fy16_unkf71_ops = {
    .read = fy16_unkf71_read, .write = fy16_unkf71_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
};


/* UNK9 */

static void fy16_unk9_write(void *opaque, hwaddr addr, uint64_t val,
                                unsigned size) {
  //Fy16State *s = opaque;
  printf("fy16_unk9_write: addr=0x%" HWADDR_PRIx " val=0x%" PRIx64
         " size=%u\n",
         addr, val, size);
}

static uint64_t fy16_unk9_read(void *opaque, hwaddr addr, unsigned size) {
  Fy16State *s = opaque;

  switch (addr)
  {
  case 0x108:
    s->dummy_time = s->dummy_time + 1;
    return s->dummy_time;
  case 0x10c:
    return 0;

  default:
    printf("fy16_unk9_read: addr=0x%" HWADDR_PRIx " size=%u\n", addr, size);
    return 0;
    break;
  }
}

static const MemoryRegionOps fy16_unk9_ops = {
    .read = fy16_unk9_read, .write = fy16_unk9_write,
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

  object_initialize_child(obj, "cpu", &s->cpu, ARM_CPU_TYPE_NAME("arm1176"));

  object_initialize_child(obj, "sflu", &s->sflu, TYPE_SOC09S_SFLU);

  s->dummy_time = 0;
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
                           get_system_memory(), fy16_memmap[RAM], 0x10000000);
  memory_region_add_subregion(get_system_memory(), fy16_memmap[RAM_REMAP1],
                              &s->ram_remap1);

  memory_region_init_alias(&s->ram_remap2, OBJECT(dev), "ram_remap2",
                           get_system_memory(), fy16_memmap[RAM], 0x10000000);
  memory_region_add_subregion(get_system_memory(), fy16_memmap[RAM_REMAP2],
                              &s->ram_remap2);

  memory_region_init_alias(&s->ram_remap3, OBJECT(dev), "ram_remap3",
                           get_system_memory(), fy16_memmap[RAM], 0x10000000);
  memory_region_add_subregion(get_system_memory(), fy16_memmap[RAM_REMAP3],
                              &s->ram_remap3);

  /* MSG_RAM */
  memory_region_init_ram(&s->msg_ram, OBJECT(dev), "msg_ram", 0x4000, errp);
  memory_region_add_subregion(get_system_memory(), fy16_memmap[MSG_RAM],
                              &s->msg_ram);

  /* TCM */
  memory_region_init_ram(&s->dtcm, OBJECT(dev), "dtcm", 4 * 1024, errp);
  memory_region_add_subregion(get_system_memory(), 0x80008000,
                              &s->dtcm);
  
  memory_region_init_ram(&s->itcm, OBJECT(dev), "itcm", 32 * 1024, errp);
  memory_region_add_subregion(get_system_memory(), 0x80000000,
                              &s->itcm);

  define_arm_cp_regs_with_opaque(&s->cpu, fy16_tcm_cp_reginfo, s);

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
  
  /* UNK4 */
  memory_region_init_io(&s->unk4, OBJECT(dev), &fy16_unk4_ops, s,
                        "unk4", 0x1000);
  memory_region_add_subregion(get_system_memory(), fy16_memmap[UNK4],
                              &s->unk4);
  
  /* UNK5 */
  memory_region_init_io(&s->unk5, OBJECT(dev), &fy16_unk5_ops, s,
                        "unk5", 0x1000);
  memory_region_add_subregion(get_system_memory(), fy16_memmap[UNK5],
                              &s->unk5);
  
  /* UNK8 */
  memory_region_init_io(&s->unk8, OBJECT(dev), &fy16_unk8_ops, s,
                        "unk8", 0x1000);
  memory_region_add_subregion(get_system_memory(), fy16_memmap[UNK8],
                              &s->unk8);
  
  /* UNKf71 */
  memory_region_init_io(&s->unkf71, OBJECT(dev), &fy16_unkf71_ops, s,
                        "unkf71", 0x1000);
  memory_region_add_subregion(get_system_memory(), fy16_memmap[UNKF0071],
                              &s->unkf71);
  
  /* UNK9 */
  memory_region_init_io(&s->unk9, OBJECT(dev), &fy16_unk9_ops, s,
                        "unk9", 0x1000);
  memory_region_add_subregion(get_system_memory(), fy16_memmap[UNK9],
                              &s->unk9);

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