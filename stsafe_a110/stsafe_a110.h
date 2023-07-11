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

#define STSAFE_A110
#define STS_CHK(ret, f)                     if ((ret) == 0) { (ret) = (f); }

struct Keys
{
    uint8_t CMAC[8*STSAFEA_HOST_KEY_LENGTH];
    uint8_t Cipher[8*STSAFEA_HOST_KEY_LENGTH];
};

class STSafeA110 {

public:
    STSafeA110();

    uint8_t init();

    int echo(uint8_t *buffer_in, uint8_t *buffer_out, size_t length);

    int update_data_partition(uint8_t zone_index, uint8_t *buf, uint16_t length);

    int read_data_partition(uint8_t zone_index, uint8_t *buf, uint16_t length);

    uint8_t generate_random(uint8_t *buf, uint16_t length);

    uint8_t pairing(uint8_t *Host_MAC_Cipher_Key);

    bool paired(void);

private:

    uint8_t _statusCode;

    Keys _key;
    
};

} // namespace sixtron

#endif // CATIE_SIXTRON_STSAFEA110_H_
