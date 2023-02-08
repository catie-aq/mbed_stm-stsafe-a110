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

    StSafeA_ResponseCode_t init();

    StSafeA_ResponseCode_t echo(uint8_t *buffer_in, uint8_t *buffer_out, size_t length);

    StSafeA_ResponseCode_t update_data_partition(uint8_t zone_index, uint8_t *buf, uint16_t length);

    StSafeA_ResponseCode_t read_data_partition(uint8_t zone_index, uint8_t *buf, uint16_t length);

private:
    StSafeA_Handle_t _stsafe_handler;
};

} // namespace sixtron

#endif // CATIE_SIXTRON_STSAFEA110_H_
