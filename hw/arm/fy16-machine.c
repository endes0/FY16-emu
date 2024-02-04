

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu/datadir.h"
#include "hw/boards.h"
#include "qemu/error-report.h"
#include "hw/arm/fy16.h"
#include "hw/loader.h"
#include "qemu/units.h"
#include "qemu/cutils.h"

static void fy16_board_init(MachineState *machine) {
  Error *err = NULL;
  Fy16State *s = FY16(object_new(TYPE_FY16));
  MachineClass *mc = MACHINE_GET_CLASS(machine);

  if (machine->ram_size != mc->default_ram_size) {
    char *sz = size_to_str(mc->default_ram_size);
    error_report("Invalid RAM size, should be %s", sz);
    g_free(sz);
    exit(EXIT_FAILURE);
  }

  if (!qdev_realize(DEVICE(s), NULL, &err)) {
    error_reportf_err(err, "Couldn't realize FY16 SoC: ");
    exit(1);
  }

  memory_region_add_subregion(get_system_memory(), 0x40000000, machine->ram);

  char *fn_rom1 =
      machine->firmware ?: qemu_find_file(QEMU_FILE_TYPE_BIOS, "fy16_1.bin");
  char *fn_rom2 = machine->kernel_filename
                      ?: qemu_find_file(QEMU_FILE_TYPE_BIOS, "fy16_2.bin");

  if (!fn_rom1 || !fn_rom2) {
    error_report("Couldn't find FY16 ROMs");
    exit(1);
  }

  ssize_t rom1_size = load_image_mr(fn_rom1, &s->rom1);
  ssize_t rom2_size = load_image_mr(fn_rom2, &s->rom2);

  if (rom1_size < 0 || rom2_size < 0) {
    error_report("Couldn't load FY16 ROMs");
    exit(1);
  }

  g_free(fn_rom1);
  g_free(fn_rom2);
}

static void fy16_machine_init(MachineClass *mc) {
  mc->desc = "FY16 (ARM1176)";
  mc->init = fy16_board_init;
  mc->default_ram_size = 128 * MiB;
  mc->default_ram_id = "ram";
}

DEFINE_MACHINE("fy16-machine", fy16_machine_init)
