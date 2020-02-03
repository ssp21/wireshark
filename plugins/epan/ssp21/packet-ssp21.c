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
#include <epan/tvbuff-int.h>

#define SSP21_FUNCTION_REQUEST_HANDSHAKE_BEGIN 0
#define SSP21_FUNCTION_REPLY_HANDSHAKE_BEGIN 1
#define SSP21_FUNCTION_REPLY_HANDSHAKE_ERROR 2
#define SSP21_FUNCTION_SESSION_DATA 3

#define SSP21_UDP_PORT 20001 /* Not IANA registed */

/// ------- names tables for enumerations -----------

static const value_string function_names[] = {
        { SSP21_FUNCTION_REQUEST_HANDSHAKE_BEGIN, "Request Handshake Begin" },
        { SSP21_FUNCTION_REPLY_HANDSHAKE_BEGIN, "Reply Handshake Begin" },
        { SSP21_FUNCTION_REPLY_HANDSHAKE_ERROR, "Reply Handshake Error" },
        { SSP21_FUNCTION_SESSION_DATA, "Session Data" },
};

static const value_string handshake_ephemeral_names[] = {
        { 0, "X25519" },
        { 1, "Nonce" },
        { 2, "None" },
};

static const value_string handshake_hash_names[] = {
        { 0, "SHA-256" },
};

static const value_string handshake_kdf_names[] = {
        { 0, "HKDF-SHA-256" },
};

static const value_string session_nonce_mode_names[] = {
        { 0, "Strict Increment" },
        { 1, "Increasing Only" },
};

static const value_string session_crypto_mode_names[] = {
        { 0, "HMAC-SHA-256 truncated to 16 bytes" },
        { 1, "AES-256-GCM" },
};

static const value_string handshake_mode_names[] = {
        { 0, "Shared Secret" },
        { 1, "Public Keys" },
        { 2, "Industrial Certificates" },
        { 3, "Quantum Key Distribution" },
};

/// ------- handles -------------------

// protocol handle
static int proto_ssp21 = -1;

/// ------- field handles -------------------
static int hf_ssp21_function = -1;
static int hf_ssp21_version = -1;

// crypto suite stuff
static int hf_ssp21_crypto_suite = -1;
static int hf_ssp21_handshake_ephemeral = -1;
static int hf_ssp21_handshake_hash = -1;
static int hf_ssp21_handshake_kdf = -1;
static int hf_ssp21_session_nonce_mode = -1;
static int hf_ssp21_session_crypto_mode = -1;

// session constraint stuff
static int hf_ssp21_session_constraints = -1;
static int hf_ssp21_max_nonce = -1;
static int hf_ssp21_max_session_duration = -1;

// handshake mode stuff
static int hf_ssp21_handshake_mode = -1;
static int hf_ssp21_mode_ephemeral = -1;
static int hf_ssp21_mode_data = -1;

// session data stuff
static int hf_ssp21_auth_metadata = -1;
static int hf_ssp21_nonce = -1;
static int hf_ssp21_valid_until_ms = -1;
static int hf_ssp21_user_data = -1;
static int hf_ssp21_auth_tag = -1;

// stuff related to variable length fields
static int hf_count_of_length_bytes = -1;
static int hf_ssp21_length = -1;
static int hf_ssp21_bytes = -1;


/// ------- subtree handles -------------------
static gint ett_ssp21 = -1;
static gint ett_ssp21_crypto_spec = -1;
static gint ett_ssp21_session_constraints = -1;
static gint ett_ssp21_seq_of_bytes = -1;
static gint ett_ssp21_auth_metadata = -1;

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
            },
            { &hf_ssp21_version,
                    { "Version", "ssp21.version",
                            FT_UINT16, BASE_DEC,
                            NULL, 0x0,
                            NULL, HFILL }
            },
            { &hf_ssp21_crypto_suite,
                        { "Crypto Suite", "ssp21.session_crypto_suite",
                                FT_NONE, BASE_NONE,
                          NULL, 0x0,
                          NULL, HFILL }
            },
            { &hf_ssp21_handshake_ephemeral,
                    { "Handshake Ephemeral", "ssp21.handshake_ephemeral",
                            FT_UINT8, BASE_DEC,
                            VALS(handshake_ephemeral_names), 0x0,
                            NULL, HFILL }
            },
            { &hf_ssp21_handshake_hash,
                    { "Handshake Hash", "ssp21.handshake_hash",
                            FT_UINT8, BASE_DEC,
                            VALS(handshake_hash_names), 0x0,
                            NULL, HFILL }
            },
            { &hf_ssp21_handshake_kdf,
                        { "Handshake KDF", "ssp21.handshake_kdf",
                          FT_UINT8, BASE_DEC,
                          VALS(handshake_kdf_names), 0x0,
                          NULL, HFILL }
            },
            { &hf_ssp21_session_nonce_mode,
                        { "Session Nonce Mode", "ssp21.session_nonce_mode",
                          FT_UINT8, BASE_DEC,
                          VALS(session_nonce_mode_names), 0x0,
                          NULL, HFILL }
            },
            { &hf_ssp21_session_crypto_mode,
                        { "Session Crypto Mode", "ssp21.session_crypto_mode",
                          FT_UINT8, BASE_DEC,
                          VALS(session_crypto_mode_names), 0x0,
                          NULL, HFILL }
            },
            { &hf_ssp21_session_constraints,
                    { "Session Constraints", "ssp21.constraints",
                            FT_NONE, BASE_NONE,
                            NULL, 0x0,
                            NULL, HFILL }
            },
            { &hf_ssp21_max_nonce,
                    { "Max Nonce", "ssp21.constraints.max_nonce",
                            FT_UINT8, BASE_DEC,
                            NULL, 0x0,
                            NULL, HFILL }
            },
            { &hf_ssp21_max_session_duration,
                    { "Max Session Duration (ms)", "ssp21.constraints.max_session_duration",
                            FT_UINT16, BASE_DEC,
                            NULL, 0x0,
                            NULL, HFILL }
            },
            { &hf_ssp21_handshake_mode,
                    { "Handshake Mode", "ssp21.handshake_mode",
                            FT_UINT8, BASE_DEC,
                            VALS(handshake_mode_names), 0x0,
                            NULL, HFILL }
            },
            { &hf_ssp21_mode_ephemeral,
                    { "Mode Ephemeral", "ssp21.mode_ephemeral",
                            FT_NONE, BASE_NONE,
                            NULL, 0x0,
                            NULL, HFILL }
            },
            { &hf_ssp21_mode_data,
                    { "Mode Data", "ssp21.mode_data",
                            FT_NONE, BASE_NONE,
                            NULL, 0x0,
                            NULL, HFILL }
            },
            { &hf_count_of_length_bytes,
                    { "Count of Length Bytes", "ssp21.count_of_length",
                            FT_UINT8, BASE_DEC,
                            NULL, 0x0,
                            NULL, HFILL }
            },
            { &hf_ssp21_length,
                        { "Length", "ssp21.length",
                                FT_UINT32, BASE_DEC,
                          NULL, 0x0,
                          NULL, HFILL }
            },
            { &hf_ssp21_bytes,
                        { "Value", "ssp21.bytes_value",
                                FT_BYTES, SEP_COLON,
                          NULL, 0x0,
                          NULL, HFILL }
            },
            { &hf_ssp21_auth_metadata,
                        { "AuthMetadata", "ssp21.auth_metadata",
                          FT_NONE, BASE_NONE,
                          NULL, 0x0,
                          NULL, HFILL }
            },
            { &hf_ssp21_nonce,
                        { "Nonce", "ssp21.nonce",
                          FT_UINT16, BASE_DEC,
                          NULL, 0x0,
                          NULL, HFILL }
            },
            { &hf_ssp21_valid_until_ms,
                        { "Valid Until Ms", "ssp21.valid_until_ms",
                          FT_UINT16, BASE_DEC,
                          NULL, 0x0,
                          NULL, HFILL }
            },
            { &hf_ssp21_user_data,
                        { "User Data", "ssp21.user_data",
                                FT_NONE, BASE_NONE,
                                NULL, 0x0,
                                NULL, HFILL }
            },
            { &hf_ssp21_auth_tag,
                    { "Auth Tag", "ssp21.auth_tag",
                            FT_NONE, BASE_NONE,
                            NULL, 0x0,
                            NULL, HFILL }
            },
    };

    // subtree array
    static gint *ett[] = {
        &ett_ssp21,
        &ett_ssp21_crypto_spec,
        &ett_ssp21_session_constraints,
        &ett_ssp21_seq_of_bytes,
        &ett_ssp21_auth_metadata,
    };

    proto_ssp21 = proto_register_protocol (
            "SSP21 Protocol",       /* name       */
            "SSP21",            /* short name */
            "ssp21"             /* abbrev     */
    );

    proto_register_field_array(proto_ssp21, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

static guint
dissect_crypto_spec(tvbuff_t *tvb, gint offset, proto_tree *parent) {

    proto_item *ti = proto_tree_add_item(parent, hf_ssp21_crypto_suite, tvb, offset, 5, ENC_NA);
    proto_tree *tree = proto_item_add_subtree(ti, ett_ssp21_crypto_spec);

    proto_tree_add_item(tree, hf_ssp21_handshake_ephemeral, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_ssp21_handshake_hash, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_ssp21_handshake_kdf, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_ssp21_session_nonce_mode, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_ssp21_session_crypto_mode, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    return offset;
}

static guint
dissect_session_constraints(tvbuff_t *tvb, gint offset, proto_tree *parent) {

    proto_item *ti = proto_tree_add_item(parent, hf_ssp21_session_constraints, tvb, offset, 6, ENC_NA);
    proto_tree *tree = proto_item_add_subtree(ti, ett_ssp21_session_constraints);

    proto_tree_add_item(tree, hf_ssp21_max_nonce, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_ssp21_max_session_duration, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    return offset;
}

static guint
dissect_auth_metadata(tvbuff_t *tvb, gint offset, proto_tree *parent) {

    proto_item *ti = proto_tree_add_item(parent, hf_ssp21_auth_metadata, tvb, offset, 6, ENC_NA);
    proto_tree *tree = proto_item_add_subtree(ti, ett_ssp21_auth_metadata);

    proto_tree_add_item(tree, hf_ssp21_nonce, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_ssp21_valid_until_ms, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    return offset;
}

static gint
dissect_seq_of_bytes(tvbuff_t *tvb, gint offset, int hf_field_handle, proto_tree *parent) {
    const gint start = offset;

    // first thing to do is attempt to read the length, b/c we need that to determine other lengths
    const guint8 first_byte = tvb_get_guint8(tvb, offset);
    const guint8 lower_bits = first_byte & 0x7Fu;
    offset += 1;

    // a single byte length
    if(!(first_byte & 0x80u)) {

        // single byte, so the length is just lower 7-bits
        const guint length = lower_bits;

        proto_item *ti = proto_tree_add_item(parent, hf_field_handle, tvb, start, length + 1, ENC_NA);
        proto_tree *tree = proto_item_add_subtree(ti, ett_ssp21_seq_of_bytes);

        proto_tree_add_item(tree, hf_ssp21_length, tvb, start, 1, ENC_BIG_ENDIAN);
        if(length > 0) {
            proto_tree_add_item(tree, hf_ssp21_bytes, tvb, offset, length, ENC_NA);
            offset += length;
        }
        return offset;
    }

    const guint8 count_of_length_bytes = lower_bits;

    switch(count_of_length_bytes) {
        case(1): {
            // TODO - ERROR if bad encoding
            const guint8 length = tvb_get_guint8(tvb, offset);

            proto_item *ti = proto_tree_add_item(parent, hf_field_handle, tvb, start, length + 2, ENC_NA);
            proto_tree *tree = proto_item_add_subtree(ti, ett_ssp21_seq_of_bytes);

            proto_tree_add_item(tree, hf_count_of_length_bytes, tvb, start, 1, ENC_BIG_ENDIAN);

            proto_tree_add_item(tree, hf_ssp21_length, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            if(length > 0) {
                proto_tree_add_item(tree, hf_ssp21_bytes, tvb, offset, length, ENC_NA);
                offset += length;
            }

            return offset;
        }
        case(2): {
            // TODO - ERROR if bad encoding
            const guint16 length = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN);

            proto_item *ti = proto_tree_add_item(parent, hf_field_handle, tvb, start, length + 3, ENC_NA);
            proto_tree *tree = proto_item_add_subtree(ti, ett_ssp21_seq_of_bytes);

            proto_tree_add_item(tree, hf_count_of_length_bytes, tvb, start, 1, ENC_BIG_ENDIAN);

            proto_tree_add_item(tree, hf_ssp21_length, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            if(length > 0) {
                proto_tree_add_item(tree, hf_ssp21_bytes, tvb, offset, length, ENC_NA);
                offset += length;
            }

            return offset;
        }
        default:
            // TODO - ERROR
            return offset;
    }
}

static guint
dissect_request_handshake_begin(tvbuff_t *tvb, gint offset, proto_tree *tree) {

    // add the version to the tree
    proto_tree_add_item(tree, hf_ssp21_version, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    offset = dissect_crypto_spec(tvb, offset, tree);
    offset = dissect_session_constraints(tvb, offset, tree);

    // handshake mode
    proto_tree_add_item(tree, hf_ssp21_handshake_mode, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    offset = dissect_seq_of_bytes(tvb, offset, hf_ssp21_mode_ephemeral, tree);
    offset = dissect_seq_of_bytes(tvb, offset, hf_ssp21_mode_data, tree);

    return offset;
}

static guint
dissect_reply_handshake_begin(tvbuff_t *tvb, gint offset, proto_tree *tree) {
    offset = dissect_seq_of_bytes(tvb, offset, hf_ssp21_mode_ephemeral, tree);
    offset = dissect_seq_of_bytes(tvb, offset, hf_ssp21_mode_data, tree);
    return offset;
}

/*
static guint
dissect_reply_handshake_error(tvbuff_t *tvb, gint offset, proto_tree *tree) {

}
*/

static guint
dissect_session_data(tvbuff_t *tvb, gint offset, proto_tree *tree) {
    offset = dissect_auth_metadata(tvb, offset, tree);
    offset = dissect_seq_of_bytes(tvb, offset, hf_ssp21_user_data, tree);
    return dissect_seq_of_bytes(tvb, offset, hf_ssp21_auth_tag, tree);
}


static int
dissect_ssp21(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
    if(tvb_captured_length(tvb) < 1) {
        return 0;
    }

    gint offset = 0;
    guint8 packet_type = tvb_get_guint8(tvb, 0);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "SSP21");
    /* Clear out stuff in the info column */
    col_clear(pinfo->cinfo,COL_INFO);

    proto_item *ti = proto_tree_add_item(tree, proto_ssp21, tvb, 0, -1, ENC_NA);
    proto_tree *ssp21_tree = proto_item_add_subtree(ti, ett_ssp21);

    // add the function code to the tree
    proto_tree_add_item(ssp21_tree, hf_ssp21_function, tvb, 0, 1, ENC_BIG_ENDIAN);
    offset += 1;

    // determine the function code and call function-specific subroutine
    switch(packet_type) {
        case(SSP21_FUNCTION_REQUEST_HANDSHAKE_BEGIN):
            offset += dissect_request_handshake_begin(tvb, offset, ssp21_tree);
            break;
        case(SSP21_FUNCTION_REPLY_HANDSHAKE_BEGIN):
            offset += dissect_reply_handshake_begin(tvb, offset, ssp21_tree);
            break;

            /*
        case(SSP21_FUNCTION_REPLY_HANDSHAKE_ERROR):
            offset += dissect_reply_handshake_error(tvb, offset, ssp21_tree);
            break;
             */

        case(SSP21_FUNCTION_SESSION_DATA):
            offset += dissect_session_data(tvb, offset, ssp21_tree);
            break;
        default:
            // TODO - ERROR on unknown function
            break;

    }

    return offset;
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
