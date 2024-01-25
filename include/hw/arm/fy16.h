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

#define TYPE_FY16 "fy16"

OBJECT_DECLARE_SIMPLE_TYPE(Fy16State, FY16)

struct Fy16State {
  /*< private >*/
  DeviceState parent_obj;
  /*< public >*/

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
  UNKF0071,
  IDC,
  UNK4,
  UNK8,
  SFLU3,
  SPIU,
  FLASH_BASE
};

#endif /* HW_ARM_FY16_H */
