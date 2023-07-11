/*
 * Copyright (c) 2023, CATIE
 * SPDX-License-Identifier: Apache-2.0
 */

#include "stsafe_a110/stsafe_a110.h"

namespace sixtron {

static StSafeA_Handle_t _stsafe_handler;

static uint8_t _rx_tx_buffer[STSAFEA_BUFFER_MAX_SIZE];

STSafeA110::STSafeA110()
{
}

uint8_t STSafeA110::init()
{
    _statusCode =  (uint8_t)StSafeA_Init(&_stsafe_handler, _rx_tx_buffer);
    return (IS_STSAFEA_HANDLER_VALID_PTR(&_stsafe_handler))? _statusCode : STSAFEA_UNEXPECTED_ERROR;
}

uint8_t STSafeA110::generate_random(uint8_t *buf, uint16_t length)
{
    StSafeA_LVBuffer_t RNG_key;
    RNG_key.Data = buf;
    RNG_key.Length = length;
    return StSafeA_GenerateRandom(&_stsafe_handler, STSAFEA_EPHEMERAL_RND, length, &RNG_key, STSAFEA_MAC_NONE);
}

uint8_t STSafeA110::pairing(uint8_t *Host_MAC_Cipher_Key)
{
    // C-MAC and Cipher keys are used to MAC the Command (C-MAC) and Response (R-MAC)

    // Host request 128b random Host C-MAC key via stsafe
    _statusCode = generate_random(_key.CMAC, STSAFEA_HOST_KEY_LENGTH);

    
    // Host request 128b random Host cipher key via stsafe
    _statusCode = generate_random(_key.CMAC, STSAFEA_HOST_KEY_LENGTH);

    // Concat to 256b pairing key
    uint8_t MAC_Cipher[2*8*STSAFEA_HOST_KEY_LENGTH];
    memcpy(MAC_Cipher, _key.CMAC, sizeof(uint8_t) * STSAFEA_HOST_KEY_LENGTH);
    memcpy(MAC_Cipher + STSAFEA_HOST_KEY_LENGTH, _key.Cipher, sizeof(uint8_t) * STSAFEA_HOST_KEY_LENGTH);


    // Check if host cipher key & host MAC key are populated
    StSafeA_HostKeySlotBuffer_t HostKeySlot;
    STS_CHK(_statusCode, StSafeA_HostKeySlotQuery(&_stsafe_handler, &HostKeySlot, STSAFEA_MAC_NONE));

    // Host send the two previous concatenated keys to the Host key slot via PUT ATTRIBUTE (needs DELETE KEY if slot already occupied)
    if ((_statusCode == STSAFEA_OK) && (HostKeySlot.HostKeyPresenceFlag == 0U)) // Not populated
    {
    /* Send both keys to STSAFE */
    // Stsafe stores the keys into their respective slots
        STS_CHK(_statusCode,
                (int32_t)StSafeA_PutAttribute(&_stsafe_handler,
                        STSAFEA_TAG_HOST_KEY_SLOT,
                        Host_MAC_Cipher_Key,
                        2 * STSAFEA_HOST_KEY_LENGTH,
                        STSAFEA_MAC_NONE));
    }

    // Host stores the keys to a secure area

    return 0;
}

bool STSafeA110::paired(void)
{
    StSafeA_HostKeySlotBuffer_t HostKeySlot;
    STS_CHK(_statusCode, StSafeA_HostKeySlotQuery(&_stsafe_handler, &HostKeySlot, STSAFEA_MAC_NONE));
    return HostKeySlot.HostKeyPresenceFlag != 0;
}

int STSafeA110::echo(uint8_t *buffer_in, uint8_t *buffer_out, size_t length)
{
    StSafeA_LVBuffer_t lv_buffer;
    lv_buffer.Data = buffer_out;
    lv_buffer.Length = length;

    return StSafeA_Echo(&_stsafe_handler, buffer_in, length, &lv_buffer, STSAFEA_MAC_NONE);
}

int STSafeA110::update_data_partition(uint8_t zone_index, uint8_t *buf, uint16_t length)
{
    StSafeA_LVBuffer_t lv_buffer;
    lv_buffer.Data = buf;
    lv_buffer.Length = length;

    return StSafeA_Update(&_stsafe_handler,
                   STSAFEA_FLAG_FALSE,
                   STSAFEA_FLAG_FALSE,
                   STSAFEA_FLAG_FALSE,
                   STSAFEA_AC_ALWAYS,
                   zone_index,
                   0,
                   &lv_buffer,
                   STSAFEA_MAC_NONE);
}

int STSafeA110::read_data_partition(uint8_t zone_index, uint8_t *buf, uint16_t length)
{
    StSafeA_LVBuffer_t lv_buffer;
    lv_buffer.Data = buf;
    lv_buffer.Length = length;

    return StSafeA_Read(&_stsafe_handler,
                   STSAFEA_FLAG_FALSE,
                   STSAFEA_FLAG_FALSE,
                   STSAFEA_AC_ALWAYS,
                   zone_index,
                   0,
                   length,
                   length,
                   &lv_buffer,
                   STSAFEA_MAC_NONE);
}

} // namespace sixtron
