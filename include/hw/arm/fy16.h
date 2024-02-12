/*
 * Misc Canon DIGIC declarations.
 *
 * Copyright (C) 2013 Antony Pavlov <antonynpavlov@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 */

#ifndef HW_ARM_FY16_H
#define HW_ARM_FY16_H

#include "cpu.h"
#include "qom/object.h"
#include "hw/ssi/soc09s_sflu.h"

#define TYPE_FY16 "fy16"

OBJECT_DECLARE_SIMPLE_TYPE(Fy16State, FY16)

struct Fy16State {
  /*< private >*/
  DeviceState parent_obj;
  /*< public >*/


  MemoryRegion rom1;
  MemoryRegion rom2;

  MemoryRegion rom1_remap;
  MemoryRegion rom2_remap;
  MemoryRegion ram_remap1;
  MemoryRegion ram_remap2;
  MemoryRegion ram_remap3;
  MemoryRegion dtcm;
  MemoryRegion itcm;

  MemoryRegion msg_ram;
  MemoryRegion asiociou;
  MemoryRegion unk4;
  MemoryRegion unk5;
  MemoryRegion unk8;
  MemoryRegion unkf71;
  MemoryRegion unk9;

  uint32_t dummy_time;

  Soc09sSflu sflu;

  //DeviceState *serial0;

  ARMCPU cpu;
};

enum {
  ROM1,
  ROM2,
  ROM1_REMAP,
  ROM2_REMAP,
  RAM,
  RAM_REMAP1,
  RAM_REMAP2,
  RAM_REMAP3,
  GOBI,
  ETH,
  EHCI_HOST,
  UNK5,
  UNK9,
  EHCI,
  ASIC_SYSCU,
  SERIAL1,
  SERIAL2,
  SERIAL3,
  UNK6,
  UNK7,
  MSG_RAM,
  ASICIOU,
  UNK10,
  UNKF0071,
  IDC,
  UNK4,
  UNK8,
  SFLU3,
  SPIU,
  FLASH_BASE
};

/* sh_serial.c */
#define TYPE_SH_SERIAL "sh-serial"
#define SH_SERIAL_FEAT_SCIF (1 << 0)

#endif /* HW_ARM_FY16_H */
