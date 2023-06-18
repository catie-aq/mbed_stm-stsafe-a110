/*
 * Copyright (c) 2023, CATIE
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef CATIE_SIXTRON_STSAFEA110_H_
#define CATIE_SIXTRON_STSAFEA110_H_

#include "mbed.h"
#include "BlockDevice.h"
#include "FlashIAPBlockDevice.h"

#include "stsafea_core.h"
#include "stsafea_types.h"

namespace sixtron {

#define FLASHIAP_ADDRESS_H753ZI 0x08100000
#define FLASHIAP_ADDRESS_L4A6RG 0x08080000
#define FLASHIAP_SIZE 0x1000

#define STS_CHK(ret, f)                     if ((ret) == 0) { (ret) = (f); }
#define PAGE_NUMBER                         255
#define ENVELOPE_SIZE                       (8*60)   /* non-zero multiple of 8 bytes; max 480(=8*60) */
#define WRAP_RESPONSE_SIZE                  (ENVELOPE_SIZE + 8) /* Local Envelope response data is 8-bytes longer than the working key (see User Manual). */

#ifdef _FORCE_DEFAULT_FLASH_
#undef USE_HOST_KEYS_SET_BY_PAIRING_APP
#define USE_HOST_KEYS_SET_BY_PAIRING_APP    0
#endif

class STSafeA110 {

public:
    STSafeA110();

    uint8_t init();

    uint8_t pairing();

    int32_t wrap_unwrap(uint8_t slot);

    int echo(uint8_t *buffer_in, uint8_t *buffer_out, size_t length);

    int update_data_partition(uint8_t zone_index, uint8_t *buf, uint16_t length);

    int read_data_partition(uint8_t zone_index, uint8_t *buf, uint16_t length);

private:
    uint8_t GenerateUnsignedChallenge(uint16_t size, uint8_t* random);

    uint8_t check_local_envelope_key();

    uint8_t check_host_keys();

    BlockDevice *bd = new FlashIAPBlockDevice(FLASHIAP_ADDRESS_H753ZI, FLASHIAP_SIZE);

    uint8_t _statusCode;

#ifdef MBED_CONF_STM_STSAFE_A110_DEBUG_LOG
    int _idx;
#endif /* MBED_CONF_STM_STSAFE_A110_DEBUG_LOG */
};

} // namespace sixtron

#endif // CATIE_SIXTRON_STSAFEA110_H_
