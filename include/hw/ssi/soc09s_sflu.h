
#ifndef SOC09S_SFLU_H
#define SOC09S_SFLU_H

#include "hw/sysbus.h"
#include "hw/ssi/ssi.h"
#include "qom/object.h"

#define TYPE_SOC09S_SFLU "soc09s-sflu"

typedef struct Soc09sSflu {
    /* <private> */
    SysBusDevice parent_obj;

    /* <public> */
    MemoryRegion mmio;
    SSIBus *ssi;
} Soc09sSflu;

#endif // SOC09S_SFLU_H