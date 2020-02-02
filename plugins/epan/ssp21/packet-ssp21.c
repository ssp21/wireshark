/* packet-ssp21.c
 *
 * Routines for SSP21 protocol packet dissection
 * By J Adam Crain <jadamcrain@automatak.com>
 * Copyright 2020 J Adam Crain
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Specification: http://ssp21.github.io
 *
 */

#include "config.h"

#include <epan/packet.h>


#define SSP21_UDP_PORT 20001 /* Not IANA registed */

static int proto_ssp21 = -1;

void
proto_register_ssp21(void)
{
    proto_ssp21 = proto_register_protocol (
            "SSP21 Protocol",       /* name       */
            "SSP21",            /* short name */
            "ssp21"             /* abbrev     */
    );
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
