#include "kia_v5.h"

// Force logging for this file only - will remove after done testing
#include <furi.h>
#define KV5_LOG(fmt, ...) furi_log_print_format(FuriLogLevelInfo, "KiaV5", fmt, ##__VA_ARGS__)

#include "../protopirate_app_i.h"
#include "keys.h"

static const SubGhzBlockConst kia_protocol_v5_const = {
    .te_short = 400,
    .te_long = 800,
    .te_delta = 150,
    .min_count_bit_for_found = 64,
};

// =============================================================================
// KEY DERIVATION
// =============================================================================

static uint8_t keystore_bytes[8] = {0};

static void build_keystore_from_mfkey(uint8_t* result) {
    uint64_t ky = get_kia_v5_key();
    for(int i = 0; i < 8; i++) {
        result[i] = (ky >> ((7 - i) * 8)) & 0xFF;
    }
}

// =============================================================================
// BIT REVERSAL HELPERS
// =============================================================================

static uint8_t reverse_byte(uint8_t b) {
    uint8_t r = 0;
    for(int i = 0; i < 8; i++) {
        if(b & (1 << i)) r |= (1 << (7 - i));
    }
    return r;
}

static uint64_t bit_reverse_64(uint64_t input) {
    uint64_t output = 0;
    for(int i = 0; i < 8; i++) {
        uint8_t byte = (input >> (i * 8)) & 0xFF;
        uint8_t reversed = reverse_byte(byte);
        output |= ((uint64_t)reversed << ((7 - i) * 8));
    }
    return output;
}

// =============================================================================
// CRC CALCULATION
// =============================================================================

static uint8_t kia_v5_calculate_crc(uint64_t yek) {
    uint8_t crc = 0;
    for(int i = 0; i < 16; i++) {
        crc ^= (yek >> (i * 4)) & 0x0F;
    }
    return crc & 0x07;
}

// =============================================================================
// DECRYPTION
// =============================================================================

static uint16_t mixer_decode(uint32_t encrypted) {
    uint8_t s0 = (encrypted & 0xFF);
    uint8_t s1 = (encrypted >> 8) & 0xFF;
    uint8_t s2 = (encrypted >> 16) & 0xFF;
    uint8_t s3 = (encrypted >> 24) & 0xFF;

    build_keystore_from_mfkey(keystore_bytes);

    int round_index = 1;
    for(size_t i = 0; i < 18; i++) {
        uint8_t r = keystore_bytes[round_index] & 0xFF;
        int steps = 8;
        while(steps > 0) {
            uint8_t base;
            if((s3 & 0x40) == 0) {
                base = (s3 & 0x02) == 0 ? 0x74 : 0x2E;
            } else {
                base = (s3 & 0x02) == 0 ? 0x3A : 0x5C;
            }

            if(s2 & 0x08) {
                base = (((base >> 4) & 0x0F) | ((base & 0x0F) << 4)) & 0xFF;
            }
            if(s1 & 0x01) {
                base = ((base & 0x3F) << 2) & 0xFF;
            }
            if(s0 & 0x01) {
                base = (base << 1) & 0xFF;
            }

            uint8_t temp = (s3 ^ s1) & 0xFF;
            s3 = ((s3 & 0x7F) << 1) & 0xFF;
            if(s2 & 0x80) {
                s3 |= 0x01;
            }
            s2 = ((s2 & 0x7F) << 1) & 0xFF;
            if(s1 & 0x80) {
                s2 |= 0x01;
            }
            s1 = ((s1 & 0x7F) << 1) & 0xFF;
            if(s0 & 0x80) {
                s1 |= 0x01;
            }
            s0 = ((s0 & 0x7F) << 1) & 0xFF;

            uint8_t chk = (base ^ (r ^ temp)) & 0xFF;
            if(chk & 0x80) {
                s0 |= 0x01;
            }
            r = ((r & 0x7F) << 1) & 0xFF;
            steps--;
        }
        round_index = (round_index - 1) & 0x7;
    }
    return (s0 + (s1 << 8)) & 0xFFFF;
}

// =============================================================================
// ENCRYPTION
// =============================================================================

#ifdef ENABLE_EMULATE_FEATURE
static uint32_t mixer_encode(uint16_t counter, uint16_t seed) {
    uint8_t s0 = counter & 0xFF;
    uint8_t s1 = (counter >> 8) & 0xFF;
    uint8_t s2 = seed & 0xFF;
    uint8_t s3 = (seed >> 8) & 0xFF;

    build_keystore_from_mfkey(keystore_bytes);

    int round_index = 0;
    for(size_t i = 0; i < 18; i++) {
        uint8_t r = keystore_bytes[round_index] & 0xFF;
        uint8_t r_reversed = reverse_byte(r);

        for(int step = 7; step >= 0; step--) {
            uint8_t out_bit = s0 & 0x01;

            s0 = ((s0 >> 1) | ((s1 & 0x01) << 7)) & 0xFF;
            s1 = ((s1 >> 1) | ((s2 & 0x01) << 7)) & 0xFF;
            s2 = ((s2 >> 1) | ((s3 & 0x01) << 7)) & 0xFF;
            s3 = (s3 >> 1) & 0xFF;

            uint8_t feedback;
            if((s3 & 0x20) == 0) {
                feedback = (s3 & 0x01) ? 0x2E : 0x74;
            } else {
                feedback = (s3 & 0x01) ? 0x5C : 0x3A;
            }

            if(s2 & 0x04) {
                feedback = ((feedback >> 4) | (feedback << 4)) & 0xFF;
            }
            if(s1 & 0x80) {
                feedback = (feedback << 2) & 0xFF;
            }
            if(s0 & 0x80) {
                feedback = (feedback << 1) & 0xFF;
            }

            feedback ^= (s3 ^ s1);
            feedback ^= ((r_reversed >> (7 - step)) & 0x01) << 7;

            if(((feedback >> 7) & 1) != out_bit) {
                s3 |= 0x80;
            }
        }

        round_index = (round_index + 1) & 0x07;
    }

    return ((uint32_t)s3 << 24) | ((uint32_t)s2 << 16) | ((uint32_t)s1 << 8) | s0;
}
#endif

// =============================================================================
// STRUCT DEFINITIONS
// =============================================================================

struct SubGhzProtocolDecoderKiaV5 {
    SubGhzProtocolDecoderBase base;
    SubGhzBlockDecoder decoder;
    SubGhzBlockGeneric generic;
    uint16_t header_count;

    ManchesterState manchester_state;
    uint64_t decoded_data;
    uint64_t saved_key;
    uint8_t bit_count;
    uint64_t yek;
    uint8_t crc;
};

#ifdef ENABLE_EMULATE_FEATURE
struct SubGhzProtocolEncoderKiaV5 {
    SubGhzProtocolEncoderBase base;
    SubGhzProtocolBlockEncoder encoder;
    SubGhzBlockGeneric generic;

    uint32_t serial;
    uint8_t button;
    uint16_t counter;
    uint64_t yek;
    uint64_t key;
    uint8_t crc;
};
#else
struct SubGhzProtocolEncoderKiaV5 {
    SubGhzProtocolEncoderBase base;
    SubGhzProtocolBlockEncoder encoder;
    SubGhzBlockGeneric generic;
};
#endif

typedef enum {
    KiaV5DecoderStepReset = 0,
    KiaV5DecoderStepCheckPreamble,
    KiaV5DecoderStepData,
} KiaV5DecoderStep;

// =============================================================================
// PROTOCOL INTERFACE DEFINITIONS
// =============================================================================

const SubGhzProtocolDecoder kia_protocol_v5_decoder = {
    .alloc = kia_protocol_decoder_v5_alloc,
    .free = kia_protocol_decoder_v5_free,
    .feed = kia_protocol_decoder_v5_feed,
    .reset = kia_protocol_decoder_v5_reset,
    .get_hash_data = kia_protocol_decoder_v5_get_hash_data,
    .serialize = kia_protocol_decoder_v5_serialize,
    .deserialize = kia_protocol_decoder_v5_deserialize,
    .get_string = kia_protocol_decoder_v5_get_string,
};

#ifdef ENABLE_EMULATE_FEATURE
const SubGhzProtocolEncoder kia_protocol_v5_encoder = {
    .alloc = kia_protocol_encoder_v5_alloc,
    .free = kia_protocol_encoder_v5_free,
    .deserialize = kia_protocol_encoder_v5_deserialize,
    .stop = kia_protocol_encoder_v5_stop,
    .yield = kia_protocol_encoder_v5_yield,
};
#else
const SubGhzProtocolEncoder kia_protocol_v5_encoder = {
    .alloc = NULL,
    .free = NULL,
    .deserialize = NULL,
    .stop = NULL,
    .yield = NULL,
};
#endif

const SubGhzProtocol kia_protocol_v5 = {
    .name = KIA_PROTOCOL_V5_NAME,
    .type = SubGhzProtocolTypeDynamic,
    .flag = SubGhzProtocolFlag_433 | SubGhzProtocolFlag_FM | SubGhzProtocolFlag_Decodable |
            SubGhzProtocolFlag_Load | SubGhzProtocolFlag_Save | SubGhzProtocolFlag_Send,
    .decoder = &kia_protocol_v5_decoder,
    .encoder = &kia_protocol_v5_encoder,
};

// =============================================================================
// ENCODER IMPLEMENTATION
// =============================================================================

#ifdef ENABLE_EMULATE_FEATURE

#define KIA_V5_PREAMBLE_PULSES    50
#define KIA_V5_TOTAL_BURSTS       3
#define KIA_V5_INTER_BURST_GAP_US 10000

// Static state — persists across encoder alloc/free cycles
// for the lifetime of the app session
static uint16_t kia_v5_last_counter = 0;
static bool kia_v5_counter_loaded = false;
static bool kia_v5_tx_done = false;

void* kia_protocol_encoder_v5_alloc(SubGhzEnvironment* environment) {
    UNUSED(environment);
    SubGhzProtocolEncoderKiaV5* instance = malloc(sizeof(SubGhzProtocolEncoderKiaV5));

    instance->base.protocol = &kia_protocol_v5;
    instance->generic.protocol_name = instance->base.protocol->name;

    instance->encoder.repeat = 1;
    instance->encoder.size_upload = 1024;
    instance->encoder.upload = malloc(instance->encoder.size_upload * sizeof(LevelDuration));
    instance->encoder.is_running = false;
    instance->encoder.front = 0;

    instance->serial = 0;
    instance->button = 0;
    instance->counter = 0;
    instance->yek = 0;
    instance->key = 0;
    instance->crc = 0;

    kia_v5_tx_done = false;

    return instance;
}

void kia_protocol_encoder_v5_free(void* context) {
    furi_check(context);
    SubGhzProtocolEncoderKiaV5* instance = context;
    if(instance->encoder.upload) {
        free(instance->encoder.upload);
    }
    free(instance);
}

static void kia_protocol_encoder_v5_update_data(SubGhzProtocolEncoderKiaV5* instance) {
    uint16_t seed = instance->serial & 0xFFFF;
    uint32_t encrypted = mixer_encode(instance->counter, seed);

    instance->yek = ((uint64_t)(instance->button & 0x0F) << 60) |
                    ((uint64_t)(instance->serial & 0x0FFFFFFF) << 32) | (uint64_t)encrypted;

    instance->crc = kia_v5_calculate_crc(instance->yek);
    instance->key = bit_reverse_64(instance->yek);

    instance->generic.data = instance->key;
    instance->generic.data_count_bit = 64;
    instance->generic.serial = instance->serial;
    instance->generic.btn = instance->button;
    instance->generic.cnt = instance->counter;

    KV5_LOG(
        "TX: Key=%08lX%08lX Yek=%08lX%08lX Sn=%07lX Btn=%X Cnt=%04X CRC=%X",
        (uint32_t)(instance->key >> 32),
        (uint32_t)(instance->key & 0xFFFFFFFF),
        (uint32_t)(instance->yek >> 32),
        (uint32_t)(instance->yek & 0xFFFFFFFF),
        (unsigned long)instance->serial,
        instance->button,
        instance->counter,
        instance->crc);
}

static void kia_protocol_encoder_v5_get_upload(SubGhzProtocolEncoderKiaV5* instance) {
    furi_check(instance);
    size_t index = 0;

    uint32_t te_short = kia_protocol_v5_const.te_short;
    uint32_t te_long = kia_protocol_v5_const.te_long;

    bool bits[67];
    for(int i = 0; i < 64; i++) {
        bits[i] = (instance->key >> (63 - i)) & 1;
    }
    for(int i = 0; i < 3; i++) {
        bits[64 + i] = (instance->crc >> (2 - i)) & 1;
    }

#define KV5_ADD(lvl, dur)                                                                         \
    do {                                                                                          \
        if(index > 0 && level_duration_get_level(instance->encoder.upload[index - 1]) == (lvl)) { \
            uint32_t prev = level_duration_get_duration(instance->encoder.upload[index - 1]);     \
            instance->encoder.upload[index - 1] = level_duration_make((lvl), prev + (dur));       \
        } else {                                                                                  \
            instance->encoder.upload[index++] = level_duration_make((lvl), (dur));                \
        }                                                                                         \
    } while(0)

    for(uint8_t burst = 0; burst < KIA_V5_TOTAL_BURSTS; burst++) {
        if(burst > 0) {
            KV5_ADD(false, KIA_V5_INTER_BURST_GAP_US);
        }

        // Preamble: alternating SHORT HIGH / SHORT LOW pairs
        for(int i = 0; i < KIA_V5_PREAMBLE_PULSES; i++) {
            KV5_ADD(true, te_short);
            KV5_ADD(false, te_short);
        }

        // Sync: LONG HIGH (consumed by preamble detector, triggers data mode)
        KV5_ADD(true, te_long);

        // Alignment: SHORT LOW (ensures level transition; absorbed by Manchester reset)
        KV5_ADD(false, te_short);

        // Manchester data encoding using prev_bit transitions.
        // After alignment LOW, line state matches "after bit=1" (both end LOW),
        // so prev_bit starts as true.
        //
        // Kia V5 Manchester polarity (level=true -> ShortHigh):
        //   prev=1, curr=1: HIGH short, LOW short   (ends LOW)
        //   prev=1, curr=0: HIGH long                (ends HIGH)
        //   prev=0, curr=0: LOW short, HIGH short    (ends HIGH)
        //   prev=0, curr=1: LOW long                 (ends LOW)
        bool prev_bit = true;

        for(int i = 0; i < 67; i++) {
            bool curr_bit = bits[i];

            if(prev_bit && curr_bit) {
                KV5_ADD(true, te_short);
                KV5_ADD(false, te_short);
            } else if(prev_bit && !curr_bit) {
                KV5_ADD(true, te_long);
            } else if(!prev_bit && curr_bit) {
                KV5_ADD(false, te_long);
            } else {
                KV5_ADD(false, te_short);
                KV5_ADD(true, te_short);
            }

            prev_bit = curr_bit;
        }

        KV5_ADD(prev_bit, te_short);
    }

#undef KV5_ADD

    instance->encoder.size_upload = index;
    instance->encoder.front = 0;

    KV5_LOG(
        "Upload: %d bursts, size=%zu, bits=%u",
        KIA_V5_TOTAL_BURSTS,
        instance->encoder.size_upload,
        instance->generic.data_count_bit);
}

SubGhzProtocolStatus
    kia_protocol_encoder_v5_deserialize(void* context, FlipperFormat* flipper_format) {
    furi_check(context);
    SubGhzProtocolEncoderKiaV5* instance = context;
    SubGhzProtocolStatus ret = SubGhzProtocolStatusError;

    instance->encoder.is_running = false;
    instance->encoder.front = 0;
    instance->encoder.repeat = 1;

    do {
        // Maybe loop happening here?
        if(kia_v5_tx_done) {
            KV5_LOG("TX already completed, blocking re-deserialize");
            break;
        }

        FuriString* temp_str = furi_string_alloc();
        if(!flipper_format_read_string(flipper_format, "Protocol", temp_str)) {
            KV5_LOG("Missing Protocol");
            furi_string_free(temp_str);
            break;
        }

        if(!furi_string_equal(temp_str, instance->base.protocol->name)) {
            KV5_LOG("Wrong protocol %s", furi_string_get_cstr(temp_str));
            furi_string_free(temp_str);
            break;
        }
        furi_string_free(temp_str);

        uint32_t bit_count_temp;
        if(!flipper_format_read_uint32(flipper_format, "Bit", &bit_count_temp, 1)) {
            KV5_LOG("Missing Bit");
            break;
        }

        instance->generic.data_count_bit = 64;

        temp_str = furi_string_alloc();
        if(!flipper_format_read_string(flipper_format, "Key", temp_str)) {
            KV5_LOG("Missing Key");
            furi_string_free(temp_str);
            break;
        }

        const char* key_str = furi_string_get_cstr(temp_str);
        uint64_t key = 0;
        size_t str_len = strlen(key_str);
        size_t hex_pos = 0;

        for(size_t i = 0; i < str_len && hex_pos < 16; i++) {
            char c = key_str[i];
            if(c == ' ') continue;

            uint8_t nibble;
            if(c >= '0' && c <= '9') {
                nibble = c - '0';
            } else if(c >= 'A' && c <= 'F') {
                nibble = c - 'A' + 10;
            } else if(c >= 'a' && c <= 'f') {
                nibble = c - 'a' + 10;
            } else {
                KV5_LOG("Invalid hex character: %c", c);
                furi_string_free(temp_str);
                break;
            }

            key = (key << 4) | nibble;
            hex_pos++;
        }

        furi_string_free(temp_str);

        if(hex_pos != 16) {
            KV5_LOG("Invalid key length: %zu nibbles", hex_pos);
            break;
        }

        instance->generic.data = key;

        if(instance->generic.data == 0) {
            KV5_LOG("Key is zero after parsing");
            break;
        }

        KV5_LOG("Parsed key: %08lX%08lX", (uint32_t)(key >> 32), (uint32_t)(key & 0xFFFFFFFF));

        if(!flipper_format_read_uint32(flipper_format, "Serial", &instance->serial, 1)) {
            uint64_t yek = bit_reverse_64(key);
            instance->serial = (uint32_t)((yek >> 32) & 0x0FFFFFFF);
            KV5_LOG("Extracted serial: 0x%07lX", (unsigned long)instance->serial);
        } else {
            KV5_LOG("Read serial: 0x%07lX", (unsigned long)instance->serial);
        }
        instance->generic.serial = instance->serial;

        uint32_t btn_temp;
        if(flipper_format_read_uint32(flipper_format, "Btn", &btn_temp, 1)) {
            instance->button = (uint8_t)btn_temp;
            KV5_LOG("Read button: 0x%X", instance->button);
        } else {
            uint64_t yek = bit_reverse_64(key);
            instance->button = (uint8_t)((yek >> 60) & 0x0F);
            KV5_LOG("Extracted button: 0x%X", instance->button);
        }
        instance->generic.btn = instance->button;

        if(!kia_v5_counter_loaded) {
            uint32_t cnt_temp;
            if(flipper_format_read_uint32(flipper_format, "Cnt", &cnt_temp, 1)) {
                instance->counter = (uint16_t)cnt_temp;
                KV5_LOG("Read counter from file: 0x%04X", instance->counter);
            } else {
                uint64_t yek = bit_reverse_64(key);
                uint32_t encrypted = (uint32_t)(yek & 0xFFFFFFFF);
                instance->counter = mixer_decode(encrypted);
                KV5_LOG("Extracted counter: 0x%04X", instance->counter);
            }
            kia_v5_counter_loaded = true;
        } else {
            instance->counter = kia_v5_last_counter;
            KV5_LOG("Using static counter: 0x%04X", instance->counter);
        }

        // Increment counter for rolling code
        uint16_t old_counter = instance->counter;
        instance->counter = (instance->counter + 1) & 0xFFFF;
        instance->generic.cnt = instance->counter;
        kia_v5_last_counter = instance->counter;
        KV5_LOG(
            "Counter incremented: 0x%04X -> 0x%04X",
            old_counter,
            instance->counter);

        // Build the signal with new counter
        kia_protocol_encoder_v5_update_data(instance);
        kia_protocol_encoder_v5_get_upload(instance);

        if(instance->encoder.size_upload == 0) {
            KV5_LOG("Upload build failed");
            ret = SubGhzProtocolStatusErrorEncoderGetUpload;
            break;
        }

        // Try to persist updated counter back to file for next app session
        flipper_format_rewind(flipper_format);
        uint32_t cnt32 = instance->counter;
        if(!flipper_format_update_uint32(flipper_format, "Cnt", &cnt32, 1)) {
            flipper_format_rewind(flipper_format);
            flipper_format_insert_or_update_uint32(flipper_format, "Cnt", &cnt32, 1);
        }

        instance->encoder.is_running = true;

        KV5_LOG(
            "Encoder ready: repeat=%u, size=%zu, Sn=%07lX Btn=%X Cnt=%04X CRC=%X",
            instance->encoder.repeat,
            instance->encoder.size_upload,
            (unsigned long)instance->serial,
            instance->button,
            instance->counter,
            instance->crc);

        ret = SubGhzProtocolStatusOk;
    } while(false);

    return ret;
}

void kia_protocol_encoder_v5_stop(void* context) {
    furi_check(context);
    SubGhzProtocolEncoderKiaV5* instance = context;
    instance->encoder.is_running = false;
    kia_v5_tx_done = false;
}

LevelDuration kia_protocol_encoder_v5_yield(void* context) {
    furi_check(context);
    SubGhzProtocolEncoderKiaV5* instance = context;

    if(!instance->encoder.is_running || instance->encoder.repeat == 0) {
        instance->encoder.is_running = false;
        kia_v5_tx_done = true;
        return level_duration_reset();
    }

    LevelDuration ret = instance->encoder.upload[instance->encoder.front];

    if(++instance->encoder.front == instance->encoder.size_upload) {
        instance->encoder.repeat--;
        instance->encoder.front = 0;
    }

    return ret;
}

#endif // ENABLE_EMULATE_FEATURE

// =============================================================================
// DECODER IMPLEMENTATION
// =============================================================================

static void kia_v5_add_bit(SubGhzProtocolDecoderKiaV5* instance, bool bit) {
    instance->decoded_data = (instance->decoded_data << 1) | (bit ? 1 : 0);
    instance->bit_count++;
    if(instance->bit_count <= 8 || instance->bit_count == 32 || instance->bit_count == 64) {
        KV5_LOG("Bit[%d]=%d data=%08lX%08lX",
            instance->bit_count - 1,
            bit ? 1 : 0,
            (uint32_t)(instance->decoded_data >> 32),
            (uint32_t)(instance->decoded_data & 0xFFFFFFFF));
    }
}

void* kia_protocol_decoder_v5_alloc(SubGhzEnvironment* environment) {
    UNUSED(environment);
    SubGhzProtocolDecoderKiaV5* instance = malloc(sizeof(SubGhzProtocolDecoderKiaV5));
    instance->base.protocol = &kia_protocol_v5;
    instance->generic.protocol_name = instance->base.protocol->name;
    return instance;
}

void kia_protocol_decoder_v5_free(void* context) {
    furi_check(context);
    SubGhzProtocolDecoderKiaV5* instance = context;
    free(instance);
}

void kia_protocol_decoder_v5_reset(void* context) {
    furi_check(context);
    SubGhzProtocolDecoderKiaV5* instance = context;
    instance->decoder.parser_step = KiaV5DecoderStepReset;
    instance->header_count = 0;
    instance->bit_count = 0;
    instance->decoded_data = 0;
    instance->saved_key = 0;
    instance->yek = 0;
    instance->crc = 0;
    instance->manchester_state = ManchesterStateMid1;
}

void kia_protocol_decoder_v5_feed(void* context, bool level, uint32_t duration) {
    furi_check(context);
    SubGhzProtocolDecoderKiaV5* instance = context;

    switch(instance->decoder.parser_step) {
    case KiaV5DecoderStepReset:
        if((level) && (DURATION_DIFF(duration, kia_protocol_v5_const.te_short) < kia_protocol_v5_const.te_delta)) {
            instance->decoder.parser_step = KiaV5DecoderStepCheckPreamble;
            instance->decoder.te_last = duration;
            instance->header_count = 1;
            instance->bit_count = 0;
            instance->decoded_data = 0;
            manchester_advance(
                instance->manchester_state,
                ManchesterEventReset,
                &instance->manchester_state,
                NULL);
        }
        break;

    case KiaV5DecoderStepCheckPreamble:
        if(level) {
            if(DURATION_DIFF(duration, kia_protocol_v5_const.te_long) < kia_protocol_v5_const.te_delta) {
                if(instance->header_count > 40) {
                    instance->decoder.parser_step = KiaV5DecoderStepData;
                    instance->bit_count = 0;
                    instance->decoded_data = 0;
                    instance->saved_key = 0;
                    instance->header_count = 0;
                } else {
                    instance->decoder.te_last = duration;
                }
            } else if(DURATION_DIFF(duration, kia_protocol_v5_const.te_short) < kia_protocol_v5_const.te_delta) {
                instance->decoder.te_last = duration;
            } else {
                instance->decoder.parser_step = KiaV5DecoderStepReset;
            }
        } else {
            if((DURATION_DIFF(duration, kia_protocol_v5_const.te_short) < kia_protocol_v5_const.te_delta) && (DURATION_DIFF(instance->decoder.te_last, kia_protocol_v5_const.te_short) < kia_protocol_v5_const.te_delta)) {
                instance->header_count++;
            } else if((DURATION_DIFF(duration, kia_protocol_v5_const.te_long) < kia_protocol_v5_const.te_delta) && (DURATION_DIFF(instance->decoder.te_last, kia_protocol_v5_const.te_short) < kia_protocol_v5_const.te_delta)) {
                instance->header_count++;
            } else if(DURATION_DIFF(instance->decoder.te_last, kia_protocol_v5_const.te_long) < kia_protocol_v5_const.te_delta) {
                instance->header_count++;
            } else {
                instance->decoder.parser_step = KiaV5DecoderStepReset;
            }
            instance->decoder.te_last = duration;
        }
        break;

    case KiaV5DecoderStepData: {
        ManchesterEvent event;

        if(DURATION_DIFF(duration, kia_protocol_v5_const.te_short) < kia_protocol_v5_const.te_delta) {
            event = level ? ManchesterEventShortHigh : ManchesterEventShortLow;
        } else if(DURATION_DIFF(duration, kia_protocol_v5_const.te_long) < kia_protocol_v5_const.te_delta) {
            event = level ? ManchesterEventLongHigh : ManchesterEventLongLow;
        } else {
            if(instance->bit_count >= kia_protocol_v5_const.min_count_bit_for_found) {
                instance->generic.data = instance->saved_key;
                instance->generic.data_count_bit = 64;

                instance->crc = (uint8_t)(instance->decoded_data & 0x07);

                instance->yek = bit_reverse_64(instance->generic.data);

                instance->generic.serial = (uint32_t)((instance->yek >> 32) & 0x0FFFFFFF);
                instance->generic.btn = (uint8_t)((instance->yek >> 60) & 0x0F);

                uint32_t encrypted = (uint32_t)(instance->yek & 0xFFFFFFFF);
                instance->generic.cnt = mixer_decode(encrypted);

                KV5_LOG(
                    "RX: Key=%08lX%08lX Yek=%08lX%08lX Sn=%07lX Btn=%X Cnt=%04lX CRC=%X",
                    (uint32_t)(instance->generic.data >> 32),
                    (uint32_t)(instance->generic.data & 0xFFFFFFFF),
                    (uint32_t)(instance->yek >> 32),
                    (uint32_t)(instance->yek & 0xFFFFFFFF),
                    instance->generic.serial,
                    instance->generic.btn,
                    instance->generic.cnt,
                    instance->crc);

                if(instance->base.callback)
                    instance->base.callback(&instance->base, instance->base.context);
            }

            instance->decoder.parser_step = KiaV5DecoderStepReset;
            break;
        }

        bool data_bit;
        if(instance->bit_count <= 66 && manchester_advance(instance->manchester_state, event, &instance->manchester_state, &data_bit)) {
            kia_v5_add_bit(instance, data_bit);

            if(instance->bit_count == 64) {
                instance->saved_key = instance->decoded_data;
                instance->decoded_data = 0;
            }
        }

        instance->decoder.te_last = duration;
        break;
    }
    }
}

uint8_t kia_protocol_decoder_v5_get_hash_data(void* context) {
    furi_check(context);
    SubGhzProtocolDecoderKiaV5* instance = context;
    return subghz_protocol_blocks_get_hash_data(
        &instance->decoder, (instance->decoder.decode_count_bit / 8) + 1);
}

SubGhzProtocolStatus kia_protocol_decoder_v5_serialize(
    void* context,
    FlipperFormat* flipper_format,
    SubGhzRadioPreset* preset) {
    furi_check(context);
    SubGhzProtocolDecoderKiaV5* instance = context;

    SubGhzProtocolStatus ret = SubGhzProtocolStatusError;

    do {
        if(!flipper_format_write_uint32(flipper_format, "Frequency", &preset->frequency, 1))
            break;

        if(!flipper_format_write_string_cstr(
               flipper_format, "Preset", furi_string_get_cstr(preset->name)))
            break;

        if(!flipper_format_write_string_cstr(
               flipper_format, "Protocol", instance->generic.protocol_name))
            break;

        uint32_t bits = 64;
        if(!flipper_format_write_uint32(flipper_format, "Bit", &bits, 1)) break;

        char key_str[20];
        snprintf(key_str, sizeof(key_str), "%016llX", instance->generic.data);
        if(!flipper_format_write_string_cstr(flipper_format, "Key", key_str)) break;

        if(!flipper_format_write_uint32(flipper_format, "Serial", &instance->generic.serial, 1))
            break;

        uint32_t temp = instance->generic.btn;
        if(!flipper_format_write_uint32(flipper_format, "Btn", &temp, 1)) break;

        if(!flipper_format_write_uint32(flipper_format, "Cnt", &instance->generic.cnt, 1)) break;

        uint32_t crc_temp = instance->crc;
        if(!flipper_format_write_uint32(flipper_format, "CRC", &crc_temp, 1)) break;

        ret = SubGhzProtocolStatusOk;
    } while(false);

    return ret;
}

SubGhzProtocolStatus
    kia_protocol_decoder_v5_deserialize(void* context, FlipperFormat* flipper_format) {
    furi_check(context);
    SubGhzProtocolDecoderKiaV5* instance = context;
    return subghz_block_generic_deserialize_check_count_bit(
        &instance->generic, flipper_format, 64);
}

void kia_protocol_decoder_v5_get_string(void* context, FuriString* output) {
    furi_check(context);
    SubGhzProtocolDecoderKiaV5* instance = context;

    uint32_t code_found_hi = instance->generic.data >> 32;
    uint32_t code_found_lo = instance->generic.data & 0x00000000ffffffff;
    uint32_t yek_hi = (uint32_t)(instance->yek >> 32);
    uint32_t yek_lo = (uint32_t)(instance->yek & 0xFFFFFFFF);

    furi_string_cat_printf(
        output,
        "%s %dbit\r\n"
        "Key:%08lX%08lX\r\n"
        "Yek:%08lX%08lX\r\n"
        "Sn:%07lX Btn:%X Cnt:%04lX\r\n"
        "CRC:%X\r\n",
        instance->generic.protocol_name,
        instance->generic.data_count_bit,
        code_found_hi,
        code_found_lo,
        yek_hi,
        yek_lo,
        instance->generic.serial,
        instance->generic.btn,
        instance->generic.cnt,
        instance->crc);
}