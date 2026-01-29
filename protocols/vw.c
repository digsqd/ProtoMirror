#include "vw.h"
#include "aut64.h"

#define TAG "VWProtocol"

static const SubGhzBlockConst subghz_protocol_vw_const = {
    .te_short = 500,
    .te_long = 1000,
    .te_delta = 120,
    .min_count_bit_for_found = 80,
};

/*
// Slightly different timings for some newer remotes?
static const SubGhzBlockConst subghz_protocol_vw3_const = {
    .te_short = 300,
    .te_long = 600,
    .te_delta = 120, // ???
    .min_count_bit_for_found = 80, // ????
};
*/

typedef struct SubGhzProtocolDecoderVw {
    SubGhzProtocolDecoderBase base;
    SubGhzBlockDecoder decoder;
    SubGhzBlockGeneric generic;

    ManchesterState manchester_state;
    uint8_t data[10];
    uint8_t type;
    uint32_t key1_low;
    uint32_t key1_high;
    uint16_t key2;
    uint8_t crc;
} SubGhzProtocolDecoderVw;

typedef struct SubGhzProtocolEncoderVw {
    SubGhzProtocolEncoderBase base;
    SubGhzProtocolBlockEncoder encoder;
    SubGhzBlockGeneric generic;
} SubGhzProtocolEncoderVw;

typedef enum {
    VwDecoderStepReset = 0,
    VwDecoderStepFoundSync,
    VwDecoderStepFoundStart1,
    VwDecoderStepFoundStart2,
    VwDecoderStepFoundStart3,
    VwDecoderStepFoundData,
} VwDecoderStep;

const SubGhzProtocolDecoder subghz_protocol_vw_decoder = {
    .alloc = subghz_protocol_decoder_vw_alloc,
    .free = subghz_protocol_decoder_vw_free,
    .feed = subghz_protocol_decoder_vw_feed,
    .reset = subghz_protocol_decoder_vw_reset,
    .get_hash_data = subghz_protocol_decoder_vw_get_hash_data,
    .serialize = subghz_protocol_decoder_vw_serialize,
    .deserialize = subghz_protocol_decoder_vw_deserialize,
    .get_string = subghz_protocol_decoder_vw_get_string,
};

const SubGhzProtocolEncoder subghz_protocol_vw_encoder = {
    .alloc = NULL,
    .free = NULL,
    .deserialize = NULL,
    .stop = NULL,
    .yield = NULL,
};

const SubGhzProtocol vw_protocol = {
    .name = VW_PROTOCOL_NAME,
    .type = SubGhzProtocolTypeDynamic,
    .flag = SubGhzProtocolFlag_433 | SubGhzProtocolFlag_AM | SubGhzProtocolFlag_Decodable |
            SubGhzProtocolFlag_Load | SubGhzProtocolFlag_Save,
    .decoder = &subghz_protocol_vw_decoder,
    .encoder = &subghz_protocol_vw_encoder,
};

#define VW_KEYS_COUNT 3

#define VW_TEA_DELTA     0x9E3779B9U
#define VW_TEA_DELTA_INC 0x61C88647U
#define VW_TEA_ROUNDS    32

static const uint32_t vw_tea_key_schedule[] = {0x2BF93A19, 0x622C1206, 0x6A55B5DA, 0xD5AAAAAA};
static const uint32_t vw_tea_key_schedule_rom[] = {0x46280509, 0xBDF0B005, 0x23084924, 0x4638466A};

///

static int8_t protocol_vw_keys_loaded = -1;
static struct aut64_key protocol_vw_keys[VW_KEYS_COUNT];

static void protocol_vw_load_keys(const char* file_name) {
    if(protocol_vw_keys_loaded >= 0) {
        FURI_LOG_I(
            TAG,
            "Already loaded %u keys from %s, skipping load",
            protocol_vw_keys_loaded,
            file_name);
        return;
    }

    FURI_LOG_I(TAG, "Loading keys from %s", file_name);

    protocol_vw_keys_loaded = 0;

    for(uint8_t i = 0; i < VW_KEYS_COUNT; i++) {
        uint8_t key_packed[AUT64_KEY_STRUCT_PACKED_SIZE];

        if(subghz_keystore_raw_get_data(
               file_name,
               i * AUT64_KEY_STRUCT_PACKED_SIZE,
               key_packed,
               AUT64_KEY_STRUCT_PACKED_SIZE)) {
            aut64_unpack(&protocol_vw_keys[i], key_packed);
            protocol_vw_keys_loaded++;
        } else {
            FURI_LOG_E(TAG, "Unable to load key %u", i);
            break;
        }
    }

    FURI_LOG_I(TAG, "Loaded %u keys", protocol_vw_keys_loaded);
}

static struct aut64_key* protocol_vw_get_key(uint8_t index) {
    for(uint8_t i = 0; i < MIN(protocol_vw_keys_loaded, VW_KEYS_COUNT); i++) {
        if(protocol_vw_keys[i].index == index) {
            return &protocol_vw_keys[i];
        }
    }

    return NULL;
}
///

static void vw_build_decoder_block(const uint8_t* key1_8, uint8_t* block_8) {
    uint32_t low = (uint32_t)key1_8[0] | ((uint32_t)key1_8[1] << 8) | ((uint32_t)key1_8[2] << 16) |
                   ((uint32_t)key1_8[3] << 24);
    uint32_t high = (uint32_t)key1_8[4] | ((uint32_t)key1_8[5] << 8) |
                    ((uint32_t)key1_8[6] << 16) | ((uint32_t)key1_8[7] << 24);
    block_8[0] = (uint8_t)(high >> 24);
    block_8[1] = (uint8_t)(high >> 16);
    block_8[2] = (uint8_t)(high >> 8);
    block_8[3] = (uint8_t)(high);
    block_8[4] = (uint8_t)(low >> 24);
    block_8[5] = (uint8_t)(low >> 16);
    block_8[6] = (uint8_t)(low >> 8);
    block_8[7] = (uint8_t)(low);
}

static void vw_tea_decrypt(uint32_t* v0, uint32_t* v1, const uint32_t* key_schedule) {
    uint32_t sum = VW_TEA_DELTA * VW_TEA_ROUNDS;
    for(int i = 0; i < VW_TEA_ROUNDS; i++) {
        uint32_t k_idx2 = (sum >> 11) & 3;
        uint32_t temp = key_schedule[k_idx2] + sum;
        *v1 -= temp ^ (((*v0 >> 5) ^ (*v0 << 4)) + *v0);
        sum -= VW_TEA_DELTA_INC;
        uint32_t k_idx1 = sum & 3;
        temp = key_schedule[k_idx1] + sum;
        *v0 -= temp ^ (((*v1 >> 5) ^ (*v1 << 4)) + *v1);
    }
}

static bool vw_manchester_advance(
    ManchesterState state,
    ManchesterEvent event,
    ManchesterState* next_state,
    bool* data) {
    bool result = false;
    ManchesterState new_state = ManchesterStateMid1;

    if(event == ManchesterEventReset) {
        new_state = ManchesterStateMid1;
    } else if(state == ManchesterStateMid0 || state == ManchesterStateMid1) {
        if(event == ManchesterEventShortHigh) {
            new_state = ManchesterStateStart1;
        } else if(event == ManchesterEventShortLow) {
            new_state = ManchesterStateStart0;
        } else {
            new_state = ManchesterStateMid1;
        }
    } else if(state == ManchesterStateStart1) {
        if(event == ManchesterEventShortLow) {
            new_state = ManchesterStateMid1;
            result = true;
            if(data) *data = true;
        } else if(event == ManchesterEventLongLow) {
            new_state = ManchesterStateStart0;
            result = true;
            if(data) *data = true;
        } else {
            new_state = ManchesterStateMid1;
        }
    } else if(state == ManchesterStateStart0) {
        if(event == ManchesterEventShortHigh) {
            new_state = ManchesterStateMid0;
            result = true;
            if(data) *data = false;
        } else if(event == ManchesterEventLongHigh) {
            new_state = ManchesterStateStart1;
            result = true;
            if(data) *data = false;
        } else {
            new_state = ManchesterStateMid1;
        }
    }

    *next_state = new_state;
    return result;
}

static void vw_add_bit(SubGhzProtocolDecoderVw* instance, bool level) {
    furi_assert(instance);

    if(instance->generic.data_count_bit >= subghz_protocol_vw_const.min_count_bit_for_found) {
        return;
    }

    if(level) {
        uint8_t byte_index = instance->generic.data_count_bit / 8;
        uint8_t bit_index = instance->generic.data_count_bit % 8;

        instance->data[byte_index] |= 1 << (7 - bit_index);
    }

    instance->generic.data_count_bit++;

    if(instance->generic.data_count_bit >= subghz_protocol_vw_const.min_count_bit_for_found) {
        if(instance->base.callback) {
            instance->base.callback(&instance->base, instance->base.context);
        } else {
            subghz_protocol_decoder_vw_reset(instance);
        }
    }
}

static void vw_fill_from_decrypted(
    SubGhzProtocolDecoderVw* instance,
    const uint8_t* dec,
    uint8_t check_byte) {
    uint64_t key1 = ((uint64_t)instance->data[0] << 56) | ((uint64_t)instance->data[1] << 48) |
                    ((uint64_t)instance->data[2] << 40) | ((uint64_t)instance->data[3] << 32) |
                    ((uint64_t)instance->data[4] << 24) | ((uint64_t)instance->data[5] << 16) |
                    ((uint64_t)instance->data[6] << 8) | (uint64_t)instance->data[7];
    instance->key1_low = (uint32_t)(key1 & 0xFFFFFFFFU);
    instance->key1_high = (uint32_t)((key1 >> 32) & 0xFFFFFFFFU);
    instance->key2 = ((uint16_t)instance->data[8] << 8) | instance->data[9];
    uint32_t serial_le = (uint32_t)dec[0] | ((uint32_t)dec[1] << 8) | ((uint32_t)dec[2] << 16) |
                         ((uint32_t)dec[3] << 24);
    instance->generic.serial = ((serial_le & 0xFFU) << 24) | ((serial_le & 0xFF00U) << 8) |
                               ((serial_le & 0xFF0000U) >> 8) | ((serial_le & 0xFF000000U) >> 24);
    instance->generic.cnt = (uint32_t)dec[4] | ((uint32_t)dec[5] << 8) | ((uint32_t)dec[6] << 16);
    instance->generic.btn = (dec[7] >> 4) & 0xFU;
    instance->crc = check_byte;
    instance->type = 0xC0;
}

static bool vw_try_aut64_block(
    SubGhzProtocolDecoderVw* instance,
    const uint8_t* block_8,
    uint8_t check_byte,
    uint8_t button_from_check,
    size_t key_start,
    size_t key_end) {
    uint8_t dec[8];
    for(size_t i = key_start; i < key_end; i++) {
        memcpy(dec, block_8, 8);
        const struct aut64_key* key = protocol_vw_get_key(i + 1);
        if(!key) {
            FURI_LOG_E(TAG, "Key not found: %zu", i + 1);
            continue;
        }
        aut64_decrypt(*key, dec);
        uint8_t btn = (dec[7] >> 4) & 0xFU;
        if(btn == button_from_check) {
            vw_fill_from_decrypted(instance, dec, check_byte);
            return true;
        }
    }
    return false;
}

static bool vw_dispatch_type_path_3_4(uint8_t t) {
    return (t == 0x2B || t == 0x1D || t == 0x47);
}

static void vw_parse_data(SubGhzProtocolDecoderVw* instance) {
    furi_assert(instance);

    instance->type = instance->data[0];
    uint8_t check_byte = instance->data[9];
    uint8_t dispatch_type = instance->data[9];
    uint8_t button_from_check = (check_byte >> 4) & 0xFU;

    uint8_t encrypted_raw[8];
    uint8_t decoder_block[8];
    memcpy(encrypted_raw, instance->data + 1, 8);
    vw_build_decoder_block(instance->data, decoder_block);

    if(vw_dispatch_type_path_3_4(dispatch_type)) {
        if(vw_try_aut64_block(instance, encrypted_raw, check_byte, button_from_check, 2, 3)) {
            return;
        }
        if(vw_try_aut64_block(instance, encrypted_raw, check_byte, button_from_check, 1, 2)) {
            return;
        }
        uint8_t dec[8];
        memcpy(dec, encrypted_raw, 8);
        const struct aut64_key* key = protocol_vw_get_key(3);

        if(!key) {
            FURI_LOG_E(TAG, "Key not found: 3");
            return;
        }
        aut64_decrypt(*key, dec);
        vw_fill_from_decrypted(instance, dec, check_byte);
        return;
    }

    if(vw_try_aut64_block(
           instance, encrypted_raw, check_byte, button_from_check, 0, VW_KEYS_COUNT)) {
        return;
    }
    if(vw_try_aut64_block(
           instance, decoder_block, check_byte, button_from_check, 0, VW_KEYS_COUNT)) {
        return;
    }
    if(instance->type == 0x00 &&
       vw_try_aut64_block(
           instance, instance->data, check_byte, button_from_check, 0, VW_KEYS_COUNT)) {
        return;
    }

    uint32_t v0 = (uint32_t)encrypted_raw[0] | ((uint32_t)encrypted_raw[1] << 8) |
                  ((uint32_t)encrypted_raw[2] << 16) | ((uint32_t)encrypted_raw[3] << 24);
    uint32_t v1 = (uint32_t)encrypted_raw[4] | ((uint32_t)encrypted_raw[5] << 8) |
                  ((uint32_t)encrypted_raw[6] << 16) | ((uint32_t)encrypted_raw[7] << 24);
    for(int tea_key = 0; tea_key < 2; tea_key++) {
        uint32_t d0 = v0;
        uint32_t d1 = v1;
        const uint32_t* key_sched = tea_key ? vw_tea_key_schedule_rom : vw_tea_key_schedule;
        vw_tea_decrypt(&d0, &d1, key_sched);
        uint8_t dec[8];
        dec[0] = (uint8_t)(d0);
        dec[1] = (uint8_t)(d0 >> 8);
        dec[2] = (uint8_t)(d0 >> 16);
        dec[3] = (uint8_t)(d0 >> 24);
        dec[4] = (uint8_t)(d1);
        dec[5] = (uint8_t)(d1 >> 8);
        dec[6] = (uint8_t)(d1 >> 16);
        dec[7] = (uint8_t)(d1 >> 24);
        uint8_t btn = (dec[7] >> 4) & 0xFU;
        if(btn == button_from_check) {
            vw_fill_from_decrypted(instance, dec, check_byte);
            return;
        }
    }
}

void* subghz_protocol_decoder_vw_alloc(SubGhzEnvironment* environment) {
    UNUSED(environment);
    SubGhzProtocolDecoderVw* instance = malloc(sizeof(SubGhzProtocolDecoderVw));
    instance->base.protocol = &vw_protocol;
    instance->generic.protocol_name = instance->base.protocol->name;
    instance->type = 0;
    instance->key1_low = 0;
    instance->key1_high = 0;
    instance->key2 = 0;
    instance->crc = 0;

    protocol_vw_load_keys(APP_ASSETS_PATH("vw"));

    return instance;
}

void subghz_protocol_decoder_vw_free(void* context) {
    furi_assert(context);
    SubGhzProtocolDecoderVw* instance = context;
    free(instance);
}

void subghz_protocol_decoder_vw_reset(void* context) {
    furi_assert(context);
    SubGhzProtocolDecoderVw* instance = context;
    instance->decoder.parser_step = VwDecoderStepReset;
    memset(instance->data, 0, 10);
    instance->generic.data_count_bit = 0;
    instance->type = 0;
    instance->key1_low = 0;
    instance->key1_high = 0;
    instance->key2 = 0;
    instance->crc = 0;
    instance->manchester_state = ManchesterStateMid1;
}

void subghz_protocol_decoder_vw_feed(void* context, bool level, uint32_t duration) {
    furi_assert(context);
    SubGhzProtocolDecoderVw* instance = context;

    uint32_t te_short = subghz_protocol_vw_const.te_short;
    uint32_t te_long = subghz_protocol_vw_const.te_long;
    uint32_t te_delta = subghz_protocol_vw_const.te_delta;
    uint32_t te_med = (te_long + te_short) / 2;
    uint32_t te_end =
        te_long * 5; // Gap to signal end of transmission (5300us on new) (none on older)

    ManchesterEvent event = ManchesterEventReset;

    switch(instance->decoder.parser_step) {
    case VwDecoderStepReset:
        if(DURATION_DIFF(duration, te_short) < te_delta) {
            instance->decoder.parser_step = VwDecoderStepFoundSync;
        }
        break;

    case VwDecoderStepFoundSync:
        if(DURATION_DIFF(duration, te_short) < te_delta) {
            break;
        }

        if(level && DURATION_DIFF(duration, te_long) < te_delta) {
            instance->decoder.parser_step = VwDecoderStepFoundStart1;
            break;
        }

        instance->decoder.parser_step = VwDecoderStepReset;
        break;

    case VwDecoderStepFoundStart1:
        if(!level && DURATION_DIFF(duration, te_short) < te_delta) {
            instance->decoder.parser_step = VwDecoderStepFoundStart2;
            break;
        }

        instance->decoder.parser_step = VwDecoderStepReset;
        break;

    case VwDecoderStepFoundStart2:
        if(level && DURATION_DIFF(duration, te_med) < te_delta) {
            instance->decoder.parser_step = VwDecoderStepFoundStart3;
            break;
        }

        instance->decoder.parser_step = VwDecoderStepReset;
        break;

    case VwDecoderStepFoundStart3:
        if(DURATION_DIFF(duration, te_med) < te_delta) {
            break;
        }

        if(level && DURATION_DIFF(duration, te_short) < te_delta) {
            vw_manchester_advance(
                instance->manchester_state,
                ManchesterEventReset,
                &instance->manchester_state,
                NULL);
            vw_manchester_advance(
                instance->manchester_state,
                ManchesterEventShortHigh,
                &instance->manchester_state,
                NULL);
            instance->generic.data_count_bit = 0;
            memset(instance->data, 0, 10);
            instance->decoder.parser_step = VwDecoderStepFoundData;
            break;
        }

        instance->decoder.parser_step = VwDecoderStepReset;
        break;

    case VwDecoderStepFoundData:
        if(DURATION_DIFF(duration, te_short) < te_delta) {
            event = level ? ManchesterEventShortHigh : ManchesterEventShortLow;
        }

        if(DURATION_DIFF(duration, te_long) < te_delta) {
            event = level ? ManchesterEventLongHigh : ManchesterEventLongLow;
        }

        if(instance->generic.data_count_bit ==
               subghz_protocol_vw_const.min_count_bit_for_found - 1 &&
           !level && duration > te_end) {
            event = ManchesterEventShortLow;
        }

        if(event == ManchesterEventReset) {
            subghz_protocol_decoder_vw_reset(instance);
        } else {
            bool new_level;
            if(vw_manchester_advance(
                   instance->manchester_state, event, &instance->manchester_state, &new_level)) {
                vw_add_bit(instance, new_level);
            }
        }
        break;
    }
}

uint8_t subghz_protocol_decoder_vw_get_hash_data(void* context) {
    furi_assert(context);
    SubGhzProtocolDecoderVw* instance = context;

    uint8_t hash = 0;
    size_t key_length = instance->generic.data_count_bit / 8;

    for(size_t i = 0; i < key_length; i++) {
        hash ^= instance->data[i];
    }

    return hash;
}

SubGhzProtocolStatus subghz_protocol_decoder_vw_serialize(
    void* context,
    FlipperFormat* flipper_format,
    SubGhzRadioPreset* preset) {
    furi_assert(context);

    SubGhzProtocolDecoderVw* instance = context;
    SubGhzProtocolStatus res = SubGhzProtocolStatusError;

    do {
        res = subghz_block_generic_serialize(&instance->generic, flipper_format, preset);
        if(res != SubGhzProtocolStatusOk) {
            break;
        }

        if(!flipper_format_rewind(flipper_format)) {
            FURI_LOG_E(TAG, "Rewind error");
            res = SubGhzProtocolStatusErrorParserOthers;
            break;
        }

        uint16_t key_length = instance->generic.data_count_bit / 8;

        if(!flipper_format_update_hex(flipper_format, "Key", instance->data, key_length)) {
            FURI_LOG_E(TAG, "Unable to update Key");
            res = SubGhzProtocolStatusErrorParserKey;
            break;
        }
    } while(false);

    return res;
}

SubGhzProtocolStatus
    subghz_protocol_decoder_vw_deserialize(void* context, FlipperFormat* flipper_format) {
    furi_assert(context);
    SubGhzProtocolDecoderVw* instance = context;

    SubGhzProtocolStatus ret =
        subghz_block_generic_deserialize(&instance->generic, flipper_format);
    if(ret != SubGhzProtocolStatusOk) {
        return ret;
    }

    instance->generic.data = 0;

    if(instance->generic.data_count_bit != subghz_protocol_vw_const.min_count_bit_for_found) {
        FURI_LOG_E(TAG, "Wrong number of bits in key");
        return SubGhzProtocolStatusErrorValueBitCount;
    }

    if(!flipper_format_rewind(flipper_format)) {
        FURI_LOG_E(TAG, "Rewind error");
        return SubGhzProtocolStatusErrorParserOthers;
    }

    size_t key_length = instance->generic.data_count_bit / 8;

    if(!flipper_format_read_hex(flipper_format, "Key", instance->data, key_length)) {
        FURI_LOG_E(TAG, "Unable to read Key in decoder");
        return SubGhzProtocolStatusErrorParserKey;
    }

    vw_parse_data(instance);

    return SubGhzProtocolStatusOk;
}

const char* vw_buttons[] = {
    "None",
    "Unlock",
    "Lock",
    "Un+Lk",
    "Trunk",
    "Un+Tr",
    "Lk+Tr",
    "Un+Lk+Tr",
    "Panic!",
    "Unlock!",
    "Lock!",
    "Un+Lk!",
    "Trunk!",
    "Un+Tr!",
    "Lk+Tr!",
    "Un+Lk+Tr!",
};

void subghz_protocol_decoder_vw_get_string(void* context, FuriString* output) {
    furi_assert(context);
    SubGhzProtocolDecoderVw* instance = context;

    if(instance->generic.data_count_bit >= subghz_protocol_vw_const.min_count_bit_for_found) {
        vw_parse_data(instance);
    }

    if(instance->type != 0xC0) {
        furi_string_cat_printf(
            output,
            "%s %dbit\r\n"
            "Type:%02X Unknown\r\n"
            "%016llX%04X\r\n",
            instance->generic.protocol_name,
            (int)instance->generic.data_count_bit,
            instance->type,
            (unsigned long long)((uint64_t)instance->data[0] << 56 |
                                 (uint64_t)instance->data[1] << 48 |
                                 (uint64_t)instance->data[2] << 40 |
                                 (uint64_t)instance->data[3] << 32 |
                                 (uint64_t)instance->data[4] << 24 |
                                 (uint64_t)instance->data[5] << 16 |
                                 (uint64_t)instance->data[6] << 8 | (uint64_t)instance->data[7]),
            (unsigned)((uint16_t)instance->data[8] << 8 | instance->data[9]));
        return;
    }

    uint64_t key1_full = ((uint64_t)instance->key1_high << 32) | instance->key1_low;
    uint8_t btn_byte = (uint8_t)(instance->generic.btn << 4);
    furi_string_cat_printf(
        output,
        "%s %dbit\r\n"
        "Key1:%016llX\r\n"
        "Key2:%04X Btn:%02X:%s\r\n"
        "Ser:%08lX Cnt:%06lX\r\n"
        "CRC:%02X\r\n",
        instance->generic.protocol_name,
        (int)instance->generic.data_count_bit,
        (unsigned long long)key1_full,
        (unsigned)instance->key2,
        (unsigned)btn_byte,
        vw_buttons[instance->generic.btn],
        (unsigned long)instance->generic.serial,
        (unsigned long)instance->generic.cnt,
        (unsigned)instance->crc);
}

void subghz_protocol_decoder_vw_get_string_brief(void* context, FuriString* output) {
    furi_assert(context);
    SubGhzProtocolDecoderVw* instance = context;
    if(instance->generic.data_count_bit >= subghz_protocol_vw_const.min_count_bit_for_found) {
        vw_parse_data(instance);
    }
    if(instance->type != 0xC0) {
        furi_string_cat_printf(output, "%s Unknown", instance->generic.protocol_name);
        return;
    }
    furi_string_cat_printf(
        output,
        "%s %08lX %s",
        instance->generic.protocol_name,
        (unsigned long)instance->generic.serial,
        vw_buttons[instance->generic.btn]);
}
