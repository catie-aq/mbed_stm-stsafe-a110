/*
 * Copyright (c) 2023, CATIE
 * SPDX-License-Identifier: Apache-2.0
 */
#include "stsafe_a110/stsafe_a110.h"
#include "stsafea_core.h"

namespace sixtron {

static StSafeA_Handle_t stsafe_handler;
static uint8_t rx_tx_buffer[STSAFEA_BUFFER_MAX_SIZE];

STSafeA110::STSafeA110()
{
}

int STSafeA110::init()
{
    return StSafeA_Init(&stsafe_handler, rx_tx_buffer) != STSAFEA_OK;
}

int STSafeA110::echo(uint8_t *buffer_in, uint8_t *buffer_out, size_t length)
{
    StSafeA_LVBuffer_t lv_buffer;
    lv_buffer.Data = buffer_out;
    lv_buffer.Length = length;

    return StSafeA_Echo(&stsafe_handler, buffer_in, length, &lv_buffer, STSAFEA_MAC_NONE)
            != STSAFEA_OK;
}

int STSafeA110::update_data_partition(uint8_t zone_index, uint8_t *buf, uint16_t length)
{
    StSafeA_LVBuffer_t lv_buffer;
    lv_buffer.Data = buf;
    lv_buffer.Length = length;

    return StSafeA_Update(&stsafe_handler,
                   STSAFEA_FLAG_FALSE,
                   STSAFEA_FLAG_FALSE,
                   STSAFEA_FLAG_FALSE,
                   STSAFEA_AC_ALWAYS,
                   zone_index,
                   0,
                   &lv_buffer,
                   STSAFEA_MAC_NONE)
            != STSAFEA_OK;
}

int STSafeA110::read_data_partition(uint8_t zone_index, uint8_t *buf, uint16_t length)
{
    StSafeA_LVBuffer_t lv_buffer;
    lv_buffer.Data = buf;
    lv_buffer.Length = length;

    return StSafeA_Read(&stsafe_handler,
                   STSAFEA_FLAG_FALSE,
                   STSAFEA_FLAG_FALSE,
                   STSAFEA_AC_ALWAYS,
                   zone_index,
                   0,
                   length,
                   length,
                   &lv_buffer,
                   STSAFEA_MAC_NONE)
            != STSAFEA_OK;
}

} // namespace sixtron
