

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu/datadir.h"
#include "hw/boards.h"
#include "qemu/error-report.h"
#include "hw/arm/digic.h"
#include "hw/block/flash.h"
#include "hw/loader.h"
#include "sysemu/qtest.h"
#include "qemu/units.h"
#include "qemu/cutils.h"

static void fy16_board_init(MachineState *machine)
{

}

static void fy16_machine_init(MachineClass *mc)
{

    mc->desc = "FY16 (ARM1176)";
    mc->init = fy16_init;
    mc->default_ram_size = 128 * MiB;
    mc->default_ram_id = "ram";
}

DEFINE_MACHINE("fy16-machine", fy16_machine_init)
