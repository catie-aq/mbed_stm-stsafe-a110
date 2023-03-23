/*
 * Copyright (c) 2023, CATIE
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef CATIE_SIXTRON_STSAFEA110_H_
#define CATIE_SIXTRON_STSAFEA110_H_

#include "mbed.h"
#include "stsafea_core.h"

namespace sixtron {

class STSafeA110 {

public:
    STSafeA110();

    int init();

    int echo(uint8_t *buffer_in, uint8_t *buffer_out, size_t length);

    int update_data_partition(uint8_t zone_index, uint8_t *buf, uint16_t length);

    int read_data_partition(uint8_t zone_index, uint8_t *buf, uint16_t length);

    int generate_random_key(uint8_t size, uint8_t *random);

    int32_t check_local_envelope_key();

    int32_t check_host_keys(uint8_t *Host_MAC_Cipher_Key, Callback<int(uint8_t *)> function);

    int32_t pairing(uint8_t *Host_MAC_Cipher_Key, Callback<int(uint8_t *)> function);
};
} // namespace sixtron

#endif // CATIE_SIXTRON_STSAFEA110_H_
