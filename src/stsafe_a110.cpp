/*
 * Copyright (c) 2023, CATIE
 * SPDX-License-Identifier: Apache-2.0
 */
#include "stsafe_a110/stsafe_a110.h"
#include "stsafea_core.h"
#include "stsafea_interface_conf.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PAGE_NUMBER 255

#define STS_CHK(ret, f)                                                                            \
    if ((ret) == 0) {                                                                              \
        (ret) = (f);                                                                               \
    }

/* Used to force default host keys storage through STM32 flash */
/* Default host keys are not stored through STSAFE-Axx */
// #define _FORCE_DEFAULT_FLASH_

#ifdef _FORCE_DEFAULT_FLASH_
#undef USE_HOST_KEYS_SET_BY_PAIRING_APP
#define USE_HOST_KEYS_SET_BY_PAIRING_APP 0
#endif

namespace sixtron {

static StSafeA_Handle_t stsafe_handler;
static uint8_t rx_tx_buffer[STSAFEA_BUFFER_MAX_SIZE];

STSafeA110::STSafeA110()
{
}

int STSafeA110::init()
{
    return StSafeA_Init(&stsafe_handler, rx_tx_buffer);
}

int STSafeA110::echo(uint8_t *buffer_in, uint8_t *buffer_out, size_t length)
{
    StSafeA_LVBuffer_t lv_buffer;
    lv_buffer.Data = buffer_out;
    lv_buffer.Length = length;

    return StSafeA_Echo(&stsafe_handler, buffer_in, length, &lv_buffer, STSAFEA_MAC_NONE);
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
            STSAFEA_MAC_NONE);
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
            STSAFEA_MAC_NONE);
}

int STSafeA110::generate_random_key(uint8_t size, uint8_t *random)
{
    if (random == NULL) {
        return (1);
    }
    StSafeA_LVBuffer_t TrueRandom;
    TrueRandom.Data = random;
    return ((uint8_t)StSafeA_GenerateRandom(
            &stsafe_handler, STSAFEA_EPHEMERAL_RND, size, &TrueRandom, STSAFEA_MAC_NONE));
}

int32_t STSafeA110::check_local_envelope_key()
{
    int32_t StatusCode = 0;
    StSafeA_LocalEnvelopeKeyTableBuffer_t LocalEnvelopeKeyTable;
    StSafeA_LocalEnvelopeKeyInformationRecordBuffer_t LocalEnvelopeInfoSlot0,
            LocalEnvelopeInfoSlot1;
    STS_CHK(StatusCode,
            (int32_t)StSafeA_LocalEnvelopeKeySlotQuery(&stsafe_handler,
                    &LocalEnvelopeKeyTable,
                    &LocalEnvelopeInfoSlot0,
                    &LocalEnvelopeInfoSlot1,
                    STSAFEA_MAC_NONE));

    if ((StatusCode == 0) && (LocalEnvelopeKeyTable.NumberOfSlots != 0U)
            && (LocalEnvelopeInfoSlot0.SlotNumber == 0U)
            && (LocalEnvelopeInfoSlot0.PresenceFlag == 0U)) {
        StatusCode = (int32_t)StSafeA_GenerateLocalEnvelopeKey(&stsafe_handler,
                STSAFEA_KEY_SLOT_0,
                STSAFEA_KEY_TYPE_AES_128,
                NULL,
                0U,
                STSAFEA_MAC_NONE);
    }

    return StatusCode;
}

int32_t STSafeA110::check_host_keys(uint8_t *Host_MAC_Cipher_Key, Callback<int(uint8_t *)> function)
{
    int32_t StatusCode = 0;
    StSafeA_HostKeySlotBuffer_t HostKeySlot;

#if USE_HOST_KEYS_SET_BY_PAIRING_APP
    /* Generate both keys */
    STS_CHK(StatusCode,
            (int32_t)generate_random_key(2 * STSAFEA_HOST_KEY_LENGTH, Host_MAC_Cipher_Key));
#endif
    /* Check if host cipher key & host MAC key are populated */
    STS_CHK(StatusCode,
            (int32_t)StSafeA_HostKeySlotQuery(&stsafe_handler, &HostKeySlot, STSAFEA_MAC_NONE));
    if ((StatusCode == 0) && (HostKeySlot.HostKeyPresenceFlag == 0U)) // Not populated
    {
        /* Send both keys to STSAFE */
        STS_CHK(StatusCode,
                (int32_t)StSafeA_PutAttribute(&stsafe_handler,
                        STSAFEA_TAG_HOST_KEY_SLOT,
                        Host_MAC_Cipher_Key,
                        2U * STSAFEA_HOST_KEY_LENGTH,
                        STSAFEA_MAC_NONE));
        /* Save both keys to STM32 FLASH */
        if (StatusCode == 0) {
            function(Host_MAC_Cipher_Key);
        }
    }
    return StatusCode;
}

int32_t STSafeA110::pairing(uint8_t *Host_MAC_Cipher_Key, Callback<int(uint8_t *)> function)
{
    int32_t StatusCode = 0;

#ifndef _FORCE_DEFAULT_FLASH_
    /* Check local envelope key */
    STS_CHK(StatusCode, check_local_envelope_key());
#endif

    /* Check cipher key & host CMAC key and provide flash sector where save both keys */
    STS_CHK(StatusCode, check_host_keys(Host_MAC_Cipher_Key, function));

    return StatusCode;
}

} // namespace sixtron
