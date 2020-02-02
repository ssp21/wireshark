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

#include <stdio.h>

#define SSP21_FUNCTION_REQUEST_HANDSHAKE_BEGIN 0
#define SSP21_FUNCTION_REPLY_HANDSHAKE_BEGIN 1
#define SSP21_FUNCTION_REPLY_HANDSHAKE_ERROR 2
#define SSP21_FUNCTION_SESSION_DATA 3

#define SSP21_UDP_PORT 20001 /* Not IANA registed */

static const value_string function_names[] = {
        { SSP21_FUNCTION_REQUEST_HANDSHAKE_BEGIN, "Request Handshake Begin" },
        { SSP21_FUNCTION_REPLY_HANDSHAKE_BEGIN, "Reply Handshake Begin" },
        { SSP21_FUNCTION_REPLY_HANDSHAKE_ERROR, "Reply Handshake Error" },
        { SSP21_FUNCTION_SESSION_DATA, "Session Data" },
        { 255, NULL },
};

// protocol handle
static int proto_ssp21 = -1;

// field handles
static int hf_ssp21_function = -1;

// subtree handles
static gint ett_ssp21 = -1;

void
proto_register_ssp21(void)
{
    // field array
    static hf_register_info hf[] = {
            { &hf_ssp21_function,
                    { "Function", "ssp21.function",
                            FT_UINT8, BASE_DEC,
                            VALS(function_names), 0x0,
                            NULL, HFILL }
            }
    };

    // subtree array
    static gint *ett[] = {
        &ett_ssp21
    };

    proto_ssp21 = proto_register_protocol (
            "SSP21 Protocol",       /* name       */
            "SSP21",            /* short name */
            "ssp21"             /* abbrev     */
    );

    proto_register_field_array(proto_ssp21, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

static int
dissect_ssp21(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
    gint offset = 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "SSP21");
    /* Clear out stuff in the info column */
    col_clear(pinfo->cinfo,COL_INFO);

    proto_item *ti = proto_tree_add_item(tree, proto_ssp21, tvb, 0, -1, ENC_NA);
    proto_tree *ssp21_tree = proto_item_add_subtree(ti, ett_ssp21);

    // add the function code to the tree
    proto_tree_add_item(ssp21_tree, hf_ssp21_function, tvb, 0, 1, ENC_BIG_ENDIAN);
    offset += 1;

    // determine the function code and call function-specific subroutine


    return tvb_captured_length(tvb);
}

void
proto_reg_handoff_ssp21(void)
{
    static dissector_handle_t ssp21_handle;

    ssp21_handle = create_dissector_handle(dissect_ssp21, proto_ssp21);
    dissector_add_for_decode_as_with_preference("udp.port", ssp21_handle);

    dissector_add_uint("udp.port", SSP21_UDP_PORT, ssp21_handle);
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
