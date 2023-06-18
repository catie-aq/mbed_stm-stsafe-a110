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
    bd->init();
    printf("\n\nFlash block device size: %llu\n", bd->size());
    printf("Flash block device read size: %llu\n", bd->get_read_size());
    printf("Flash block device program size: %llu\n", bd->get_program_size());
    printf("Flash block device erase size: %llu\n", bd->get_erase_size());

#ifdef MBED_CONF_STM_STSAFE_A110_DEBUG_LOG
    _idx = 0;
#endif /* MBED_CONF_STM_STSAFE_A110_DEBUG_LOG */
}

uint8_t STSafeA110::init()
{
    return (uint8_t)StSafeA_Init(&_stsafe_handler, _rx_tx_buffer);
}

int STSafeA110::echo(uint8_t *buffer_in, uint8_t *buffer_out, size_t length)
{
    StSafeA_LVBuffer_t lv_buffer;
    lv_buffer.Data = buffer_out;
    lv_buffer.Length = length;

    return StSafeA_Echo(&_stsafe_handler, buffer_in, length, &lv_buffer, STSAFEA_MAC_NONE)
            != STSAFEA_OK;
}

uint8_t STSafeA110::pairing()
{
    _statusCode = 0;

#ifdef MBED_CONF_STM_STSAFE_A110_DEBUG_LOG
    _idx = 0;
    printf("\n\r\n\r\n\rPairing demonstration:");
#endif /* MBED_CONF_STM_STSAFE_A110_DEBUG_LOG */

#ifndef _FORCE_DEFAULT_FLASH_
    /* Check local envelope key */
    STS_CHK(_statusCode, check_local_envelope_key());
#endif

    /* Check cipher key & host CMAC key and provide flash sector where save both keys */
    STS_CHK(_statusCode, check_host_keys());

    return _statusCode;
}

int32_t STSafeA110::wrap_unwrap(uint8_t slot)
{
    _statusCode = 0;
    uint8_t Random[ENVELOPE_SIZE];

#ifdef MBED_CONF_STM_STSAFE_A110_DEBUG_LOG
    _idx = 0;
    printf("\n\r\n\rWrap/unwrap local envelope demonstration:");
#endif /* MBED_CONF_STM_STSAFE_A110_DEBUG_LOG */

    /* Declare, define and allocate memory for Wrap Local Envelope */
#if (STSAFEA_USE_OPTIMIZATION_SHARED_RAM)
    StSafeA_LVBuffer_t LocalEnvelope;
#else
    StSafeA_LVBuffer_t LocalEnvelope;
    uint8_t data_LocalEnvelope [WRAP_RESPONSE_SIZE] = {0};
    LocalEnvelope.Length = WRAP_RESPONSE_SIZE;
    LocalEnvelope.Data = data_LocalEnvelope;
#endif /* STSAFEA_USE_OPTIMIZATION_SHARED_RAM */

    /* Generate random */
#ifdef MBED_CONF_STM_STSAFE_A110_DEBUG_LOG
    printf("\n\r %d. Generate local envelope (random data) of %d bytes", ++_idx, ENVELOPE_SIZE);
    printf("\n\r    => Use StSafeA_WrapLocalEnvelope API");
#endif /* MBED_CONF_STM_STSAFE_A110_DEBUG_LOG */

    STS_CHK(_statusCode, (int32_t)GenerateUnsignedChallenge(ENVELOPE_SIZE, &Random[0]));
    printf(" [STS_CHK: 0x%02X]", _statusCode);

#ifdef MBED_CONF_STM_STSAFE_A110_DEBUG_LOG
    printf("\n\r %d. Wrap local envelope", ++_idx);
    printf("\n\r    => Use StSafeA_WrapLocalEnvelope API");
#endif /* MBED_CONF_STM_STSAFE_A110_DEBUG_LOG */

    /* Wrap local envelope using key slot as argument */
    STS_CHK(_statusCode, (int32_t)StSafeA_WrapLocalEnvelope(&_stsafe_handler, slot, &Random[0], ENVELOPE_SIZE, &LocalEnvelope,
                                                            STSAFEA_MAC_HOST_CMAC, STSAFEA_ENCRYPTION_COMMAND));
    printf(" [STS_CHK: 0x%02X]", _statusCode);

    if (_statusCode == STSAFEA_OK) {
    #if (STSAFEA_USE_OPTIMIZATION_SHARED_RAM)
        /* Store Wrapped Local Envelope */
        uint8_t data_WrappedEnvelope[WRAP_RESPONSE_SIZE];
        (void)memcpy(data_WrappedEnvelope, LocalEnvelope.Data, LocalEnvelope.Length);
        LocalEnvelope.Data = data_WrappedEnvelope;
    #endif /* STSAFEA_USE_OPTIMIZATION_SHARED_RAM */

        /* Declare, define and allocate memory for Unwrap Local Envelope */
    #if (STSAFEA_USE_OPTIMIZATION_SHARED_RAM)
        StSafeA_LVBuffer_t UnwrappedEnvelope;
    #else
        StSafeA_LVBuffer_t UnwrappedEnvelope;
        uint8_t data_UnwrappedEnvelope [ENVELOPE_SIZE] = {0};
        UnwrappedEnvelope.Length = ENVELOPE_SIZE;
        UnwrappedEnvelope.Data = data_UnwrappedEnvelope;
    #endif /* STSAFEA_USE_OPTIMIZATION_SHARED_RAM */

#ifdef MBED_CONF_STM_STSAFE_A110_DEBUG_LOG
    printf("\n\r %d. Unrap local envelope", ++_idx);
    printf("\n\r    => Use StSafeA_UnwrapLocalEnvelope API");
#endif /* MBED_CONF_STM_STSAFE_A110_DEBUG_LOG */

    /* Unwrap local envelope using key in slot as argument */
    STS_CHK(_statusCode, (int32_t)StSafeA_UnwrapLocalEnvelope(&_stsafe_handler, slot, LocalEnvelope.Data,
                                                            LocalEnvelope.Length, &UnwrappedEnvelope,
                                                            STSAFEA_MAC_HOST_CMAC, STSAFEA_ENCRYPTION_RESPONSE));
    printf(" [STS_CHK: 0x%02X]", _statusCode);

#ifdef MBED_CONF_STM_STSAFE_A110_DEBUG_LOG
        printf("\n\r %d. Verify unwrap local envelope is identical to initial generated envelope", ++_idx);
#endif /* MBED_CONF_STM_STSAFE_A110_DEBUG_LOG */
        if ((_statusCode == STSAFEA_OK) && (memcmp(&Random[0], &UnwrappedEnvelope.Data[0], ENVELOPE_SIZE) != 0)) {
            _statusCode = (uint8_t)~0U;
        }
    }

#ifdef MBED_CONF_STM_STSAFE_A110_DEBUG_LOG
    printf("\n\r %d. Local envelope Local envelope demonstration result (0x0 means success): 0x%x", ++_idx, (int)_statusCode);
#endif /* MBED_CONF_STM_STSAFE_A110_DEBUG_LOG */

    return _statusCode;
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
                   STSAFEA_MAC_NONE)
            != STSAFEA_OK;
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
                   STSAFEA_MAC_NONE)
            != STSAFEA_OK;
}

uint8_t STSafeA110::GenerateUnsignedChallenge(uint16_t size, uint8_t* random)
{
    STSAFEA_UNUSED_PTR(_stsafe_handler);

    if (random == NULL) {
        return (1);
    }

#ifdef MBED_CONF_STM_STSAFE_A110_DEBUG_LOG
    printf("\n\r %d. Generate a %d bytes random number", ++_idx, size);
    printf("\n\r    => Use StSafeA_GenerateRandom API");
#endif /* MBED_CONF_STM_STSAFE_A110_DEBUG_LOG */

    StSafeA_LVBuffer_t TrueRandom;
    TrueRandom.Data = random;
    return ((uint8_t)StSafeA_GenerateRandom(&_stsafe_handler, STSAFEA_EPHEMERAL_RND, size, &TrueRandom, STSAFEA_MAC_NONE));
}

uint8_t STSafeA110::check_local_envelope_key()
{
    _statusCode = 0;
    StSafeA_LocalEnvelopeKeyTableBuffer_t LocalEnvelopeKeyTable;
    StSafeA_LocalEnvelopeKeyInformationRecordBuffer_t  LocalEnvelopeInfoSlot0, LocalEnvelopeInfoSlot1;

#ifdef MBED_CONF_STM_STSAFE_A110_DEBUG_LOG
    printf("\n\r %d. Check local envelope key presence through STSAFE-A1x0", ++_idx);
    printf("\n\r        => StSafeA_LocalEnvelopeKeySlotQuery");
#endif /* MBED_CONF_STM_STSAFE_A110_DEBUG_LOG */

    STS_CHK(_statusCode, (int32_t)StSafeA_LocalEnvelopeKeySlotQuery(&_stsafe_handler, &LocalEnvelopeKeyTable, &LocalEnvelopeInfoSlot0,
                                                                 &LocalEnvelopeInfoSlot1, STSAFEA_MAC_NONE));
    printf(" [STS_CHK: 0x%02X]", _statusCode);

    if ((_statusCode == 0 ) && (LocalEnvelopeKeyTable.NumberOfSlots != 0U) && (LocalEnvelopeInfoSlot0.SlotNumber == 0U) && (LocalEnvelopeInfoSlot0.PresenceFlag == 0U)) {
#ifdef MBED_CONF_STM_STSAFE_A110_DEBUG_LOG
        printf("\n\r %d. Generate local envelope key", ++_idx);
        printf("\n\r        => StSafeA_GenerateLocalEnvelopeKey");
#endif /* MBED_CONF_STM_STSAFE_A110_DEBUG_LOG */

        _statusCode = (int32_t)StSafeA_GenerateLocalEnvelopeKey(&_stsafe_handler, STSAFEA_KEY_SLOT_0, STSAFEA_KEY_TYPE_AES_128, NULL, 0U, STSAFEA_MAC_NONE);
        printf("\n[STS_CHK: 0x%02X]\n", _statusCode);
    }

    return _statusCode;
}

uint8_t STSafeA110::check_host_keys()
{
    _statusCode = 0;
    uint8_t Host_MAC_Cipher_Key[2U * STSAFEA_HOST_KEY_LENGTH] = {
        0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,    /* Host MAC key */
        0x11,0x11,0x22,0x22,0x33,0x33,0x44,0x44,0x55,0x55,0x66,0x66,0x77,0x77,0x88,0x88     /* Host cipher key */
    };
    uint32_t i;
    uint64_t ptr;
    StSafeA_HostKeySlotBuffer_t HostKeySlot;

//    if (!(IS_FLASH_PAGE(PAGE_NUMBER))) {
//#ifdef MBED_CONF_STM_STSAFE_A110_DEBUG_LOG
//        printf("\n\r    %d Flash page out of range", _idx);
//#endif /* MBED_CONF_STM_STSAFE_A110_DEBUG_LOG */
//        return 1;   
//    }

#if USE_HOST_KEYS_SET_BY_PAIRING_APP
    /* Generate both keys */
    STS_CHK(_statusCode, (int32_t)GenerateUnsignedChallenge(&_stsafe_handler, 2 * STSAFEA_HOST_KEY_LENGTH, Host_MAC_Cipher_Key));
#endif

#ifdef MBED_CONF_STM_STSAFE_A110_DEBUG_LOG
    printf("\n\r %d. Check host keys presence through STSAFE-A1x0", ++_idx);
    printf("\n\r        => StSafeA_HostKeySlotQuery");
#endif /* MBED_CONF_STM_STSAFE_A110_DEBUG_LOG */

    /* Check if host cipher key & host MAC key are populated */
    STS_CHK(_statusCode, (int32_t)StSafeA_HostKeySlotQuery(&_stsafe_handler, &HostKeySlot, STSAFEA_MAC_NONE));
    printf(" [STS_CHK: 0x%02X]", _statusCode);

#ifdef _FORCE_DEFAULT_FLASH_
    if (_statusCode == 0) {
#else
    if ((_statusCode == 0) && (HostKeySlot.HostKeyPresenceFlag == 0U)) {      // Not populated
#ifdef MBED_CONF_STM_STSAFE_A110_DEBUG_LOG
        printf("\n\r %d. Set host keys through STSAFE-A1x0", ++_idx);
        printf("\n\r        => StSafeA_PutAttribute");
#endif /* MBED_CONF_STM_STSAFE_A110_DEBUG_LOG */

        /* Send both keys to STSAFE */
        STS_CHK(_statusCode, (int32_t)StSafeA_PutAttribute(&_stsafe_handler, STSAFEA_TAG_HOST_KEY_SLOT,
                                                        Host_MAC_Cipher_Key, 2U * STSAFEA_HOST_KEY_LENGTH,
                                                        STSAFEA_MAC_NONE));
#endif

#ifdef MBED_CONF_STM_STSAFE_A110_DEBUG_LOG
        printf("\n\r %d. Store host keys through STM32 flash memory", ++_idx);
#endif /* MBED_CONF_STM_STSAFE_A110_DEBUG_LOG */

        /* Save both keys to STM32 FLASH */
        if (_statusCode == STSAFEA_OK)
        {
            if (bd->erase(0, bd->size()) != 0) {
                return -1;
            }

            if (bd->program(Host_MAC_Cipher_Key, 0, bd->get_erase_size()) != 0) {
                return -2;
            }

            if (bd->sync() != 0) {
                return -3;
            }

            _statusCode = STSAFEA_OK;
        }
    }

    return _statusCode;
}

} // namespace sixtron
