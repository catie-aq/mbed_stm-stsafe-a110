/*
 * Copyright (c) 2023, CATIE
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef CATIE_SIXTRON_STSAFEA110_H_
#define CATIE_SIXTRON_STSAFEA110_H_

#include "mbed.h"

namespace sixtron {

class STSafeA110 {

public:
    STSafeA110();

    int init();

    int echo(uint8_t *buffer_in, uint8_t *buffer_out, size_t length);

    int update_data_partition(uint8_t zone_index, uint8_t *buf, uint16_t length);

    int read_data_partition(uint8_t zone_index, uint8_t *buf, uint16_t length);
};

} // namespace sixtron

#endif // CATIE_SIXTRON_STSAFEA110_H_
