/**
 * Copyright (c) 2012 - 2021, Nordic Semiconductor ASA
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form, except as embedded into a Nordic
 *    Semiconductor ASA integrated circuit in a product or a software update for
 *    such product, must reproduce the above copyright notice, this list of
 *    conditions and the following disclaimer in the documentation and/or other
 *    materials provided with the distribution.
 *
 * 3. Neither the name of Nordic Semiconductor ASA nor the names of its
 *    contributors may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 * 4. This software, with or without modification, must only be used with a
 *    Nordic Semiconductor ASA integrated circuit.
 *
 * 5. Any software provided in binary form under this license must not be reverse
 *    engineered, decompiled, modified and/or disassembled.
 *
 * THIS SOFTWARE IS PROVIDED BY NORDIC SEMICONDUCTOR ASA "AS IS" AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY, NONINFRINGEMENT, AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL NORDIC SEMICONDUCTOR ASA OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */
#include "sdk_common.h"

#include "ble.h"
#include "ble_gfp.h"
#include "ble_srv_common.h"
#include "nrf_crypto.h"
#include "nrf_crypto_ecc.h"
#include "nrf_crypto_ecdh.h"
#include "nrf_crypto_error.h"
#include "nrf_crypto_hash.h"
#define NRF_LOG_MODULE_NAME ble_gfp
#if BLE_GFP_CONFIG_LOG_ENABLED
#define NRF_LOG_LEVEL       BLE_GFP_CONFIG_LOG_LEVEL
#define NRF_LOG_INFO_COLOR  BLE_GFP_CONFIG_INFO_COLOR
#define NRF_LOG_DEBUG_COLOR BLE_GFP_CONFIG_DEBUG_COLOR
#else // BLE_GFP_CONFIG_LOG_ENABLED
#define NRF_LOG_LEVEL       4
#endif // BLE_GFP_CONFIG_LOG_ENABLED
#include "nrf_log.h"
NRF_LOG_MODULE_REGISTER();
/** Length of ECDH public key (512 bits = 64 bytes). */
#define FP_CRYPTO_ECDH_PUBLIC_KEY_LEN		64U
/** Length of AES-128 block (128 bits = 16 bytes). */
#define FP_CRYPTO_AES128_BLOCK_LEN		16U
/** Length of ECDH shared key (256 bits = 32 bytes). */
#define FP_CRYPTO_ECDH_SHARED_KEY_LEN		32U
/** Fast Pair Anti-Spoofing private key length (256 bits = 32 bytes). */
#define FP_REG_DATA_ANTI_SPOOFING_PRIV_KEY_LEN	32U

#define FP_KBP_FLAG_INITIATE_BONDING 0x02

#define BLE_UUID_GFP_MODEL_ID_CHARACTERISTIC 0x1233             
#define BLE_UUID_GFP_KEY_BASED_PAIRING_CHARACTERISTIC 0x1234
#define BLE_UUID_GFP_PASSKEY_CHARACTERISTIC 0x1235 
#define BLE_UUID_GFP_ACCOUNT_KEY_CHARACTERISTIC 0x1236 
#define BLE_UUID_GFP_ADDI_DATA_CHARACTERISTIC 0x1237                 

#define BLE_GFP_MAX_RX_CHAR_LEN        BLE_GFP_MAX_DATA_LEN /**< Maximum length of the RX Characteristic (in bytes). */
#define BLE_GFP_MAX_TX_CHAR_LEN        BLE_GFP_MAX_DATA_LEN /**< Maximum length of the TX Characteristic (in bytes). */

#define GFP_CHARACTERISTIC_BASE_UUID                  {{0xEA, 0x0B, 0x10, 0x32, 0xDE, 0x01, 0xB0, 0x8E, 0x14, 0x48, 0x66, 0x83, 0x00, 0x00, 0x2C, 0xFE}} /**< Used vendor specific UUID. */

#define GFP_SERVICE_UUID  0xFE2C

/* Fast Pair message type. */
enum fp_msg_type {
	/* Key-based Pairing Request. */
	FP_MSG_KEY_BASED_PAIRING_REQ    = 0x00,

	/* Key-based Pairing Response. */
	FP_MSG_KEY_BASED_PAIRING_RSP    = 0x01,

	/* Seeker's Passkey. */
	FP_MSG_SEEKERS_PASSKEY          = 0x02,

	/* Provider's Passkey. */
	FP_MSG_PROVIDERS_PASSKEY        = 0x03,

	/* Action request. */
	FP_MSG_ACTION_REQ               = 0x10,
};

static uint8_t anti_spoofing_priv_key[FP_REG_DATA_ANTI_SPOOFING_PRIV_KEY_LEN]={0x52 , 0x7a , 0x21 , 0xfa , 0x7c , 0x9c , 0x2b , 0xf6 , 0x49 , 0xee , 0x4d , 0xdd , 0x1e , 0xc7 , 0x5c , 0x36 , 0x98 , 0x8f , 0xd5 , 0x27 , 0xce , 0xcb , 0x43 , 0xff , 0x2f , 0x1e , 0x57 , 0x8b , 0x1c , 0x98 , 0xa2 , 0x2b};

struct msg_kbp_req_data {
	uint8_t seeker_address[6];
};

struct msg_action_req_data {
	uint8_t msg_group;
	uint8_t msg_code;
	uint8_t additional_data_len_or_id;
	uint8_t additional_data[5];
};

union kbp_write_msg_specific_data {
	struct msg_kbp_req_data kbp_req;
	struct msg_action_req_data action_req;
};

struct msg_kbp_write {
	uint8_t msg_type;
	uint8_t fp_flags;
	uint8_t provider_address[6];
	union kbp_write_msg_specific_data data;
};

struct msg_seekers_passkey {
	uint8_t msg_type;
	uint32_t passkey;
};

static uint8_t  Anti_Spoofing_AES_Key[NRF_CRYPTO_HASH_SIZE_SHA256];
//function
static  void gfp_memcpy_swap(void *dst, const void *src, size_t length)
{
	uint8_t *pdst = (uint8_t *)dst;
	const uint8_t *psrc = (const uint8_t *)src;

	ASSERT(((psrc < pdst && (psrc + length) <= pdst) ||
		  (psrc > pdst && (pdst + length) <= psrc)));

	psrc += length - 1;

	for (; length > 0; length--) {
		*pdst++ = *psrc--;
	}
}
//crypto
static void print_array(uint8_t const * p_string, size_t size)
{
    #if NRF_LOG_ENABLED
    size_t i;
    NRF_LOG_RAW_INFO("    ");
    for(i = 0; i < size; i++)
    {
        NRF_LOG_RAW_INFO("%02x ", p_string[i]);
    }
    #endif // NRF_LOG_ENABLED
}


static void print_hex(char const * p_msg, uint8_t const * p_data, size_t size)
{
    NRF_LOG_INFO(p_msg);
    print_array(p_data, size);
    NRF_LOG_RAW_INFO("\r\n");
}
static ret_code_t fp_crypto_ecdh_shared_secret(uint8_t *secret_key, const uint8_t *public_key,
				 const uint8_t *private_key)
{
     nrf_crypto_ecc_private_key_t              alice_private_key;
     nrf_crypto_ecc_public_key_t               bob_public_key;

    ret_code_t                                       err_code = NRF_SUCCESS;
    size_t                                           size;

    size = FP_CRYPTO_ECDH_PUBLIC_KEY_LEN;

    // Alice converts Bob's raw public key to internal representation
    err_code = nrf_crypto_ecc_public_key_from_raw(&g_nrf_crypto_ecc_secp256r1_curve_info,
                                                  &bob_public_key,
                                                  public_key, size);
    if(NRF_SUCCESS != err_code)
    {
      return err_code;
    }

    //  converts  raw private key to internal representation
    err_code = nrf_crypto_ecc_private_key_from_raw(&g_nrf_crypto_ecc_secp256r1_curve_info,
                                                   &alice_private_key,
                                                   private_key,
                                                   32);
    if(NRF_SUCCESS != err_code)
    {
      return err_code;
    }

    //  computes shared secret using ECDH
    size = FP_CRYPTO_ECDH_SHARED_KEY_LEN;
    err_code = nrf_crypto_ecdh_compute(NULL,
                                       &alice_private_key,
                                       &bob_public_key,
                                       secret_key,
                                       &size);
    if(NRF_SUCCESS != err_code)
    {
      return err_code;
    }

    // Alice can now use shared secret
    //print_hex("Alice's shared secret: ", secret_key, size);

    // Key deallocation
    err_code = nrf_crypto_ecc_private_key_free(&alice_private_key);
    
    err_code = nrf_crypto_ecc_public_key_free(&bob_public_key);
    

    return err_code;
}

#if 0
/**@brief Function for handling the @ref BLE_GAP_EVT_CONNECTED event from the SoftDevice.
 *
 * @param[in] p_gfp     Nordic UART Service structure.
 * @param[in] p_ble_evt Pointer to the event received from BLE stack.
 */
static void on_connect(ble_gfp_t * p_gfp, ble_evt_t const * p_ble_evt)
{
    ret_code_t                 err_code;
    ble_gfp_evt_t              evt;
    ble_gatts_value_t          gatts_val;
    uint8_t                    cccd_value[2];
    ble_gfp_client_context_t * p_client = NULL;

    err_code = blcm_link_ctx_get(p_gfp->p_link_ctx_storage,
                                 p_ble_evt->evt.gap_evt.conn_handle,
                                 (void *) &p_client);
    if (err_code != NRF_SUCCESS)
    {
        NRF_LOG_ERROR("Link context for 0x%02X connection handle could not be fetched.",
                      p_ble_evt->evt.gap_evt.conn_handle);
    }
 NRF_LOG_INFO("on_connect################################\n");

    /* Check the hosts CCCD value to inform of readiness to send data using the RX characteristic */
    memset(&gatts_val, 0, sizeof(ble_gatts_value_t));
    gatts_val.p_value = cccd_value;
    gatts_val.len     = sizeof(cccd_value);
    gatts_val.offset  = 0;

    err_code = sd_ble_gatts_value_get(p_ble_evt->evt.gap_evt.conn_handle,
                                      p_gfp->keybase_pair_handles.cccd_handle,
                                      &gatts_val);

    if ((err_code == NRF_SUCCESS))
    {
       NRF_LOG_INFO("get keybase_pair_handles################################%d\n",err_code);
    }

        memset(&gatts_val, 0, sizeof(ble_gatts_value_t));
    gatts_val.p_value = cccd_value;
    gatts_val.len     = sizeof(cccd_value);
    gatts_val.offset  = 0;

    err_code = sd_ble_gatts_value_get(p_ble_evt->evt.gap_evt.conn_handle,
                                      p_gfp->addi_data_handles.cccd_handle,
                                      &gatts_val);

    if ((err_code == NRF_SUCCESS))
    {
       NRF_LOG_INFO("get addi_data_handles################################%d\n",err_code);
    }

            memset(&gatts_val, 0, sizeof(ble_gatts_value_t));
    gatts_val.p_value = cccd_value;
    gatts_val.len     = sizeof(cccd_value);
    gatts_val.offset  = 0;

    err_code = sd_ble_gatts_value_get(p_ble_evt->evt.gap_evt.conn_handle,
                                      p_gfp->passkey_handles.cccd_handle,
                                      &gatts_val);

    //if ((err_code == NRF_SUCCESS))
    {
       NRF_LOG_INFO("get passkey_handles################################%d\n",err_code);
    }



}
#endif


/**@brief Function for handling the @ref BLE_GATTS_EVT_WRITE event from the SoftDevice.
 *
 * @param[in] p_gfp     Nordic UART Service structure.
 * @param[in] p_ble_evt Pointer to the event received from BLE stack.
 */
static void on_write(ble_gfp_t * p_gfp, ble_evt_t const * p_ble_evt)
{
    ret_code_t                    err_code;
    ble_gfp_evt_t                 evt;
//    ble_gfp_client_context_t    * p_client;
    ble_gatts_evt_write_t const * p_evt_write = &p_ble_evt->evt.gatts_evt.params.write;


    //err_code = blcm_link_ctx_get(p_gfp->p_link_ctx_storage,
    //                             p_ble_evt->evt.gatts_evt.conn_handle,
    //                             (void *) &p_client);
    //if (err_code != NRF_SUCCESS)
    //{
    //    NRF_LOG_ERROR("Link context for 0x%02X connection handle could not be fetched.",
    //                  p_ble_evt->evt.gatts_evt.conn_handle);
    //}

    //memset(&evt, 0, sizeof(ble_gfp_evt_t));
    //evt.p_gfp       = p_gfp;
    //evt.conn_handle = p_ble_evt->evt.gatts_evt.conn_handle;
    //evt.p_link_ctx  = p_client;
 NRF_LOG_INFO("on_write################################\n");
    if ((p_evt_write->handle == p_gfp->keybase_pair_handles.cccd_handle) &&
        (p_evt_write->len == 2))
    {
        //if (p_client != NULL)
        //{
        //    if (ble_srv_is_notification_enabled(p_evt_write->data))
        //    {
        //        p_client->is_notification_enabled = true;
        //        evt.type                          = BLE_GFP_EVT_COMM_STARTED;
        //    }
        //    else
        //    {
        //        p_client->is_notification_enabled = false;
        //        evt.type                          = BLE_GFP_EVT_COMM_STOPPED;
        //    }

        //    if (p_gfp->data_handler != NULL)
        //    {
        //        p_gfp->data_handler(&evt);
        //    }

        //}
           NRF_LOG_INFO("keybase_pair_ccchandles################################%d&  %d\n",ble_srv_is_notification_enabled(p_evt_write->data),ble_srv_is_indication_enabled(p_evt_write->data));
 
           

    }
    else if ((p_evt_write->handle == p_gfp->passkey_handles.cccd_handle) &&
        (p_evt_write->len == 2))
    {
        //if (p_client != NULL)
        //{
        //    if (ble_srv_is_notification_enabled(p_evt_write->data))
        //    {
        //        p_client->is_notification_enabled = true;
        //        evt.type                          = BLE_GFP_EVT_COMM_STARTED;
        //    }
        //    else
        //    {
        //        p_client->is_notification_enabled = false;
        //        evt.type                          = BLE_GFP_EVT_COMM_STOPPED;
        //    }

        //    if (p_gfp->data_handler != NULL)
        //    {
        //        p_gfp->data_handler(&evt);
        //    }

        //}
         NRF_LOG_INFO("passkey_ccchandles################################\n");
    }
     else if ((p_evt_write->handle == p_gfp->addi_data_handles.cccd_handle) &&
        (p_evt_write->len == 2))
    {
        //if (p_client != NULL)
        //{
        //    if (ble_srv_is_notification_enabled(p_evt_write->data))
        //    {
        //        p_client->is_notification_enabled = true;
        //        evt.type                          = BLE_GFP_EVT_COMM_STARTED;
        //    }
        //    else
        //    {
        //        p_client->is_notification_enabled = false;
        //        evt.type                          = BLE_GFP_EVT_COMM_STOPPED;
        //    }

        //    if (p_gfp->data_handler != NULL)
        //    {
        //        p_gfp->data_handler(&evt);
        //    }

        //}
      NRF_LOG_INFO("addi_data_ccchandles################################%d&  %d\n",ble_srv_is_notification_enabled(p_evt_write->data),ble_srv_is_indication_enabled(p_evt_write->data));
    }
    else if ((p_evt_write->handle == p_gfp->keybase_pair_handles.value_handle) )
    {
        //evt.type                  = BLE_GFP_EVT_RX_DATA;
        //evt.params.rx_data.p_data = p_evt_write->data;
        //evt.params.rx_data.length = p_evt_write->len;

        //p_gfp->data_handler(&evt);
        //uint8_t req_enc[FP_CRYPTO_AES128_BLOCK_LEN];
        //uint8_t public_key[FP_CRYPTO_ECDH_PUBLIC_KEY_LEN];
        uint8_t ecdh_secret[FP_CRYPTO_ECDH_SHARED_KEY_LEN];
        NRF_LOG_INFO("rev len %d\n",p_evt_write->len);
        //for(int i=0;i< p_evt_write->len;i++)
        //{
           //NRF_LOG_INFO(" 0x%x ,",p_evt_write->data[i]);
           
        //}
#if 0
             uint8_t raw_key_buffer[]={

0x36, 0xAC, 0x68, 0x2C, 0x50, 0x82, 0x15, 0x66, 0x8F, 0xBE, 0xFE, 0x24,
0x7D, 0x01, 0xD5, 0xEB, 0x96, 0xE6, 0x31, 0x8E, 0x85, 0x5B, 0x2D, 0x64,
0xB5, 0x19, 0x5D, 0x38, 0xEE, 0x7E, 0x37, 0xBE, 0x18, 0x38, 0xC0, 0xB9,
0x48, 0xC3, 0xF7, 0x55, 0x20, 0xE0, 0x7E, 0x70, 0xF0, 0x72, 0x91, 0x41,
0x9A, 0xCE, 0x2D, 0x28, 0x14, 0x3C, 0x5A, 0xDB, 0x2D, 0xBD, 0x98, 0xEE,
0x3C, 0x8E, 0x4F, 0xBF
    };
      uint8_t m_alice_raw_private_key[] =
{

0x02, 0xB4, 0x37, 0xB0, 0xED, 0xD6, 0xBB, 0xD4, 0x29, 0x06, 0x4A, 0x4E,
0x52, 0x9F, 0xCB, 0xF1, 0xC4, 0x8D, 0x0D, 0x62, 0x49, 0x24, 0xD5, 0x92,
0x27, 0x4B, 0x7E, 0xD8, 0x11, 0x93, 0xD7, 0x63
};
        fp_crypto_ecdh_shared_secret(ecdh_secret,raw_key_buffer,
                                      m_alice_raw_private_key);
#endif
        err_code = fp_crypto_ecdh_shared_secret(ecdh_secret,(p_evt_write->data)+FP_CRYPTO_AES128_BLOCK_LEN,
                                      anti_spoofing_priv_key);
        if(NRF_SUCCESS != err_code)
        {
          NRF_LOG_ERROR("fp_crypto_ecdh_shared_secret err %x\n",err_code);
        }

         // Alice can now use shared secret
        print_hex(" shared secret: ", ecdh_secret, FP_CRYPTO_ECDH_SHARED_KEY_LEN);

        nrf_crypto_hash_context_t   hash_context;
        //uint8_t  Anti_Spoofing_AES_Key[NRF_CRYPTO_HASH_SIZE_SHA256];
        size_t digest_len = NRF_CRYPTO_HASH_SIZE_SHA256;

           // Initialize the hash context
        err_code = nrf_crypto_hash_init(&hash_context, &g_nrf_crypto_hash_sha256_info);
        if(NRF_SUCCESS != err_code)
        {
          NRF_LOG_ERROR("nrf_crypto_hash_init err %x\n",err_code);
        }

    // Run the update function (this can be run multiples of time if the data is accessible
    // in smaller chunks, e.g. when received on-air.
        err_code = nrf_crypto_hash_update(&hash_context, ecdh_secret, FP_CRYPTO_ECDH_SHARED_KEY_LEN);
        if(NRF_SUCCESS != err_code)
        {
          NRF_LOG_ERROR("nrf_crypto_hash_update err %x\n",err_code);
        }

    // Run the finalize when all data has been fed to the update function.
    // this gives you the result
        err_code = nrf_crypto_hash_finalize(&hash_context, Anti_Spoofing_AES_Key, &digest_len);
        if(NRF_SUCCESS != err_code)
        {
          NRF_LOG_ERROR("nrf_crypto_hash_finalize err %x\n",err_code);
        }
        // NRF_LOG_INFO("keybase_pair_handles################################\n");

        nrf_crypto_aes_info_t const * p_ecb_info;
   
        nrf_crypto_aes_context_t      ecb_decr_ctx;
        p_ecb_info = &g_nrf_crypto_aes_ecb_128_info;
        size_t      len_out;
        uint8_t raw_req[FP_CRYPTO_AES128_BLOCK_LEN];
        err_code = nrf_crypto_aes_init(&ecb_decr_ctx,
                                  p_ecb_info,
                                  NRF_CRYPTO_DECRYPT);
        if(NRF_SUCCESS != err_code)
        {
          NRF_LOG_ERROR("nrf_crypto_aes_init err %x\n",err_code);
        }

        /* Set encryption and decryption key */

        err_code = nrf_crypto_aes_key_set(&ecb_decr_ctx, Anti_Spoofing_AES_Key);
        if(NRF_SUCCESS != err_code)
        {
          NRF_LOG_ERROR("nrf_crypto_aes_key_set err %x\n",err_code);
        }

        /* Decrypt blocks */
        len_out = sizeof(raw_req);
        err_code = nrf_crypto_aes_finalize(&ecb_decr_ctx,
                                      (uint8_t *)p_evt_write->data,
                                      FP_CRYPTO_AES128_BLOCK_LEN,
                                      (uint8_t *)raw_req,
                                      &len_out);
        if(NRF_SUCCESS != err_code)
        {
          NRF_LOG_ERROR("nrf_crypto_aes_finalize err %x\n",err_code);
        }
//NRF_LOG_ERROR("@@nrf_crypto_aes_finalize err %x\n",err_code);
        struct msg_kbp_write parsed_req;
        parsed_req.msg_type = raw_req[0];
        parsed_req.fp_flags = raw_req[1];
        gfp_memcpy_swap(parsed_req.provider_address, raw_req+2,
			sizeof(parsed_req.provider_address));

        switch (parsed_req.msg_type) {
	case FP_MSG_KEY_BASED_PAIRING_REQ:
		gfp_memcpy_swap(parsed_req.data.kbp_req.seeker_address, raw_req+8,
				sizeof(parsed_req.data.kbp_req.seeker_address)); 

		break;

	case FP_MSG_ACTION_REQ:
		parsed_req.data.action_req.msg_group = raw_req[8];
		parsed_req.data.action_req.msg_code = raw_req[9];
		parsed_req.data.action_req.additional_data_len_or_id = raw_req[10];

		memcpy(parsed_req.data.action_req.additional_data, raw_req+11,
		       sizeof(parsed_req.data.action_req.additional_data));

		break;

	default:
		NRF_LOG_ERROR("Unexpected message type: 0x%x (Key-based Pairing)",
			parsed_req.msg_type);
		
	}
        NRF_LOG_INFO("requ:%x %x\n",parsed_req.msg_type,parsed_req.fp_flags);
        print_hex(" raw_req: ", raw_req, 16);

        print_hex(" provider_address: ", parsed_req.provider_address, 6);

        ble_gap_addr_t addr;
        err_code = sd_ble_gap_addr_get(&addr);
        if(NRF_SUCCESS != err_code)
        {
          NRF_LOG_ERROR("sd_ble_gap_addr_get err %x\n",err_code);
        }
        
    
        uint8_t rsp[FP_CRYPTO_AES128_BLOCK_LEN];
        rsp[0] = FP_MSG_KEY_BASED_PAIRING_RSP;
        gfp_memcpy_swap(rsp+1, addr.addr,6);
        print_hex("rsp: ", rsp, 16);

        nrf_crypto_aes_context_t      ecb_encr_ctx;
        uint8_t encrypted_rsp[FP_CRYPTO_AES128_BLOCK_LEN];
        len_out = 16;
           /* Encrypt text with integrated function */
        err_code = nrf_crypto_aes_crypt(&ecb_encr_ctx,
                                   p_ecb_info,
                                   NRF_CRYPTO_ENCRYPT,
                                   Anti_Spoofing_AES_Key,
                                   NULL,
                                   (uint8_t *)rsp,
                                   16,
                                   (uint8_t *)encrypted_rsp,
                                   &len_out);
        if(NRF_SUCCESS != err_code)
        {
          NRF_LOG_ERROR("nrf_crypto_aes_crypt err %x\n",err_code);
        }

        ble_gatts_hvx_params_t     hvx_params;
        memset(&hvx_params, 0, sizeof(hvx_params));
        len_out = FP_CRYPTO_AES128_BLOCK_LEN;
        hvx_params.handle = p_gfp->keybase_pair_handles.value_handle;
        hvx_params.p_data = encrypted_rsp;
        hvx_params.p_len  = &len_out;
        hvx_params.type   = BLE_GATT_HVX_NOTIFICATION;

        err_code = sd_ble_gatts_hvx(p_ble_evt->evt.gatts_evt.conn_handle, &hvx_params);
         if(NRF_SUCCESS != err_code)
        {
          NRF_LOG_ERROR("sd_ble_gatts_hvx err %x\n",err_code);
        }



                     

    }
    else if ((p_evt_write->handle == p_gfp->passkey_handles.value_handle) )
    {
        //evt.type                  = BLE_GFP_EVT_RX_DATA;
        //evt.params.rx_data.p_data = p_evt_write->data;
        //evt.params.rx_data.length = p_evt_write->len;

        //p_gfp->data_handler(&evt);
         NRF_LOG_INFO("passkey_handles################################\n");
        nrf_crypto_aes_info_t const * p_ecb_info_passkey;
   
        nrf_crypto_aes_context_t      ecb_decr_ctx_passkey;
        p_ecb_info_passkey = &g_nrf_crypto_aes_ecb_128_info;
        size_t      len_out_passkey;
        uint8_t raw_req_passkey[FP_CRYPTO_AES128_BLOCK_LEN];
        err_code = nrf_crypto_aes_init(&ecb_decr_ctx_passkey,
                                  p_ecb_info_passkey,
                                  NRF_CRYPTO_DECRYPT);
        if(NRF_SUCCESS != err_code)
        {
          NRF_LOG_ERROR("nrf_crypto_aes_init err %x\n",err_code);
        }

        /* Set encryption and decryption key */

        err_code = nrf_crypto_aes_key_set(&ecb_decr_ctx_passkey, Anti_Spoofing_AES_Key);
        if(NRF_SUCCESS != err_code)
        {
          NRF_LOG_ERROR("nrf_crypto_aes_key_set err %x\n",err_code);
        }

        /* Decrypt blocks */
        len_out_passkey = sizeof(raw_req_passkey);
        err_code = nrf_crypto_aes_finalize(&ecb_decr_ctx_passkey,
                                      (uint8_t *)p_evt_write->data,
                                      FP_CRYPTO_AES128_BLOCK_LEN,
                                      (uint8_t *)raw_req_passkey,
                                      &len_out_passkey);
        if(NRF_SUCCESS != err_code)
        {
          NRF_LOG_ERROR("nrf_crypto_aes_finalize err %x\n",err_code);
        }

        struct msg_seekers_passkey parsed_req_passkey;
        parsed_req_passkey.msg_type = raw_req_passkey[0];
        parsed_req_passkey.passkey  = (raw_req_passkey[1] << 16) | (raw_req_passkey[2] << 8) | raw_req_passkey[3];

        err_code = sd_ble_gap_auth_key_reply(p_ble_evt->evt.gatts_evt.conn_handle, BLE_GAP_AUTH_KEY_TYPE_PASSKEY, NULL);
        if (err_code != NRF_SUCCESS) 
        {
          NRF_LOG_ERROR("Failed to confirm passkey (err %d)\n", err_code);
        }

        // resp
         uint8_t rsp_passkey[FP_CRYPTO_AES128_BLOCK_LEN];
         rsp_passkey[0] = FP_MSG_PROVIDERS_PASSKEY;
         rsp_passkey[1] = raw_req_passkey[1];
         rsp_passkey[2] = raw_req_passkey[2];
         rsp_passkey[3] = raw_req_passkey[3];

        nrf_crypto_aes_context_t      ecb_encr_ctx_passkey;
        uint8_t encrypted_rsp_passkey[FP_CRYPTO_AES128_BLOCK_LEN];
        len_out_passkey = 16;
           /* Encrypt text with integrated function */
        err_code = nrf_crypto_aes_crypt(&ecb_encr_ctx_passkey,
                                   p_ecb_info_passkey,
                                   NRF_CRYPTO_ENCRYPT,
                                   Anti_Spoofing_AES_Key,
                                   NULL,
                                   (uint8_t *)rsp_passkey,
                                   16,
                                   (uint8_t *)encrypted_rsp_passkey,
                                   &len_out_passkey);
        if(NRF_SUCCESS != err_code)
        {
          NRF_LOG_ERROR("nrf_crypto_aes_crypt err %x\n",err_code);
        }

        ble_gatts_hvx_params_t     hvx_params_passkey;
        memset(&hvx_params_passkey, 0, sizeof(hvx_params_passkey));
        len_out_passkey = FP_CRYPTO_AES128_BLOCK_LEN;
        hvx_params_passkey.handle = p_gfp->passkey_handles.value_handle;
        hvx_params_passkey.p_data = encrypted_rsp_passkey;
        hvx_params_passkey.p_len  = &len_out_passkey;
        hvx_params_passkey.type   = BLE_GATT_HVX_NOTIFICATION;

        err_code = sd_ble_gatts_hvx(p_ble_evt->evt.gatts_evt.conn_handle, &hvx_params_passkey);
         if(NRF_SUCCESS != err_code)
        {
          NRF_LOG_ERROR("sd_ble_gatts_hvx err %x\n",err_code);
        }
        NRF_LOG_INFO("passkey_handles################################end\n");
                     

    }
        else if ((p_evt_write->handle == p_gfp->account_key_handles.value_handle) )
    {
        //evt.type                  = BLE_GFP_EVT_RX_DATA;
        //evt.params.rx_data.p_data = p_evt_write->data;
        //evt.params.rx_data.length = p_evt_write->len;

        //p_gfp->data_handler(&evt);
         NRF_LOG_INFO("account_key_handles################################\n");
                      

    }
    else if ((p_evt_write->handle == p_gfp->addi_data_handles.value_handle) )
    {
        //evt.type                  = BLE_GFP_EVT_RX_DATA;
        //evt.params.rx_data.p_data = p_evt_write->data;
        //evt.params.rx_data.length = p_evt_write->len;

        //p_gfp->data_handler(&evt);
         NRF_LOG_INFO("addi_data_handles################################\n");
                      

    }
    else
    {
        // Do Nothing. This event is not relevant for this service.
    }
}

#if 0
/**@brief Function for handling the @ref BLE_GATTS_EVT_HVN_TX_COMPLETE event from the SoftDevice.
 *
 * @param[in] p_gfp     Nordic UART Service structure.
 * @param[in] p_ble_evt Pointer to the event received from BLE stack.
 */
static void on_hvx_tx_complete(ble_gfp_t * p_gfp, ble_evt_t const * p_ble_evt)
{
    ret_code_t                 err_code;
    ble_gfp_evt_t              evt;
    ble_gfp_client_context_t * p_client;

    err_code = blcm_link_ctx_get(p_gfp->p_link_ctx_storage,
                                 p_ble_evt->evt.gatts_evt.conn_handle,
                                 (void *) &p_client);
    if (err_code != NRF_SUCCESS)
    {
        NRF_LOG_ERROR("Link context for 0x%02X connection handle could not be fetched.",
                      p_ble_evt->evt.gatts_evt.conn_handle);
        return;
    }

    if ((p_client->is_notification_enabled) && (p_gfp->data_handler != NULL))
    {
        memset(&evt, 0, sizeof(ble_gfp_evt_t));
        evt.type        = BLE_GFP_EVT_TX_RDY;
        evt.p_gfp       = p_gfp;
        evt.conn_handle = p_ble_evt->evt.gatts_evt.conn_handle;
        evt.p_link_ctx  = p_client;

        p_gfp->data_handler(&evt);
    }
}
#endif

void ble_gfp_on_ble_evt(ble_evt_t const * p_ble_evt, void * p_context)
{
    if ((p_context == NULL) || (p_ble_evt == NULL))
    {
        return;
    }

    ble_gfp_t * p_gfp = (ble_gfp_t *)p_context;

    switch (p_ble_evt->header.evt_id)
    {
        case BLE_GAP_EVT_CONNECTED:
            //on_connect(p_gfp, p_ble_evt);
            break;

        case BLE_GATTS_EVT_WRITE:
            on_write(p_gfp, p_ble_evt);
            break;

        case BLE_GATTS_EVT_HVN_TX_COMPLETE:
            //on_hvx_tx_complete(p_gfp, p_ble_evt);
            break;

        default:
            // No implementation needed.
            break;
    }
}


uint32_t ble_gfp_init(ble_gfp_t * p_gfp, ble_gfp_init_t const * p_gfp_init)
{
    ret_code_t            err_code;
    ble_uuid_t            ble_uuid;
    ble_uuid128_t         gfp_character_base_uuid = GFP_CHARACTERISTIC_BASE_UUID;
    ble_add_char_params_t add_char_params;
    uint8_t               character_uuid_type=0;
    uint8_t model_id[] = {0x2a, 0x41, 0x0b}; // model_id
    VERIFY_PARAM_NOT_NULL(p_gfp);
    VERIFY_PARAM_NOT_NULL(p_gfp_init);
 NRF_LOG_INFO("ble_gfp_init################################\n");    // Initialize the service structure.
    p_gfp->data_handler = p_gfp_init->data_handler;
    

    /**@snippet [Adding proprietary Service to the SoftDevice] 
    // Add a custom base UUID.
    err_code = sd_ble_uuid_vs_add(&gfp_base_uuid, &p_gfp->uuid_type);
    VERIFY_SUCCESS(err_code);*/
   // Add service
    BLE_UUID_BLE_ASSIGN(ble_uuid, GFP_SERVICE_UUID);

    //ble_uuid.type = p_gfp->uuid_type;
    //ble_uuid.uuid = BLE_UUID_GFP_SERVICE;
    p_gfp->uuid_type = ble_uuid.type;
    // Add the service.
    err_code = sd_ble_gatts_service_add(BLE_GATTS_SRVC_TYPE_PRIMARY,
                                        &ble_uuid,
                                        &p_gfp->service_handle);
    /**@snippet [Adding proprietary Service to the SoftDevice] */
    VERIFY_SUCCESS(err_code);

NRF_LOG_INFO("2\n"); 
     // Add a custom base UUID.
    err_code = sd_ble_uuid_vs_add(&gfp_character_base_uuid, &character_uuid_type);
    VERIFY_SUCCESS(err_code);
    // Add the RX Characteristic.
    memset(&add_char_params, 0, sizeof(add_char_params));
    add_char_params.uuid                     = BLE_UUID_GFP_MODEL_ID_CHARACTERISTIC;
    add_char_params.uuid_type                = character_uuid_type;
    add_char_params.max_len                  = 3;
    add_char_params.init_len                 = 3;
    add_char_params.p_init_value             = model_id;
    //add_char_params.is_var_len               = true;
    //add_char_params.char_props.write         = 1;
    add_char_params.char_props.read = 1;
    //add_char_params.char_props.write_wo_resp = 1;
    add_char_params.read_access  = SEC_OPEN;
    add_char_params.write_access = SEC_OPEN;

    err_code = characteristic_add(p_gfp->service_handle, &add_char_params, &p_gfp->model_id_handles);
    if (err_code != NRF_SUCCESS)
    {
        return err_code;
    }
NRF_LOG_INFO("3\n"); 
    // Add the key base pairing Characteristic.
    /**@snippet [Adding proprietary characteristic to the SoftDevice] */
    memset(&add_char_params, 0, sizeof(add_char_params));
    add_char_params.uuid              = BLE_UUID_GFP_KEY_BASED_PAIRING_CHARACTERISTIC;
    add_char_params.uuid_type         = character_uuid_type;
    add_char_params.max_len           = BLE_GFP_MAX_TX_CHAR_LEN;
    add_char_params.init_len          = sizeof(uint8_t);
    add_char_params.is_var_len        = true;
    add_char_params.char_props.notify = 1;
    add_char_params.char_props.write  = 1;

    add_char_params.read_access       = SEC_OPEN;
    add_char_params.write_access      = SEC_OPEN;
    add_char_params.cccd_write_access = SEC_OPEN;

    err_code = characteristic_add(p_gfp->service_handle, &add_char_params, &p_gfp->keybase_pair_handles);
    if (err_code != NRF_SUCCESS)
    {
        return err_code;
    }
NRF_LOG_INFO("4\n"); 
#if 1
     // Add the passkey  Characteristic.
    /**@snippet [Adding proprietary characteristic to the SoftDevice] */
    memset(&add_char_params, 0, sizeof(add_char_params));
    add_char_params.uuid              = BLE_UUID_GFP_PASSKEY_CHARACTERISTIC;
    add_char_params.uuid_type         = character_uuid_type;
    add_char_params.max_len           = 200;
    add_char_params.init_len          = sizeof(uint8_t);
    add_char_params.is_var_len        = true;
    add_char_params.char_props.notify = 1;
    add_char_params.char_props.write  = 1;

    add_char_params.read_access       = SEC_OPEN;
    add_char_params.write_access      = SEC_OPEN;
    add_char_params.cccd_write_access = SEC_OPEN;

    err_code = characteristic_add(p_gfp->service_handle, &add_char_params, &p_gfp->passkey_handles);
    if (err_code != NRF_SUCCESS)
    {
        return err_code;
    }
NRF_LOG_INFO("5\n"); 
    // Add the account key  Characteristic.
    /**@snippet [Adding proprietary characteristic to the SoftDevice] */
    memset(&add_char_params, 0, sizeof(add_char_params));
    add_char_params.uuid              = BLE_UUID_GFP_ACCOUNT_KEY_CHARACTERISTIC;
    add_char_params.uuid_type         = character_uuid_type;
    add_char_params.max_len           = 200;
    add_char_params.init_len          = sizeof(uint8_t);
    add_char_params.is_var_len        = true;
    //add_char_params.char_props.notify = 1;
    add_char_params.char_props.write  = 1;

    add_char_params.read_access       = SEC_OPEN;
    add_char_params.write_access      = SEC_OPEN;
    //add_char_params.cccd_write_access = SEC_OPEN;

    err_code = characteristic_add(p_gfp->service_handle, &add_char_params, &p_gfp->account_key_handles);
    if (err_code != NRF_SUCCESS)
    {NRF_LOG_INFO("err_code %x\n",err_code); 
        return err_code;
    }

NRF_LOG_INFO("6\n"); 
    // Add the addi data Characteristic.
    /**@snippet [Adding proprietary characteristic to the SoftDevice] */
    memset(&add_char_params, 0, sizeof(add_char_params));
    add_char_params.uuid              = BLE_UUID_GFP_ADDI_DATA_CHARACTERISTIC;
    add_char_params.uuid_type         = character_uuid_type;
    add_char_params.max_len           = 100;
    add_char_params.init_len          = sizeof(uint8_t);
    add_char_params.is_var_len        = true;
    add_char_params.char_props.notify = 1;
    add_char_params.char_props.write  = 1;

    add_char_params.read_access       = SEC_OPEN;
    add_char_params.write_access      = SEC_OPEN;
    add_char_params.cccd_write_access = SEC_OPEN;

    err_code = characteristic_add(p_gfp->service_handle, &add_char_params, &p_gfp->addi_data_handles);
    if (err_code != NRF_SUCCESS)
    {
        return err_code;
    }
#endif
    NRF_LOG_INFO("7\n"); 
    return NRF_SUCCESS;
}

#if 0
uint32_t ble_gfp_data_send(ble_gfp_t * p_gfp,
                           uint8_t   * p_data,
                           uint16_t  * p_length,
                           uint16_t    conn_handle)
{
    ret_code_t                 err_code;
    ble_gatts_hvx_params_t     hvx_params;
    ble_gfp_client_context_t * p_client;

    VERIFY_PARAM_NOT_NULL(p_gfp);

    err_code = blcm_link_ctx_get(p_gfp->p_link_ctx_storage, conn_handle, (void *) &p_client);
    VERIFY_SUCCESS(err_code);

    if ((conn_handle == BLE_CONN_HANDLE_INVALID) || (p_client == NULL))
    {
        return NRF_ERROR_NOT_FOUND;
    }

    if (!p_client->is_notification_enabled)
    {
        return NRF_ERROR_INVALID_STATE;
    }

    if (*p_length > BLE_GFP_MAX_DATA_LEN)
    {
        return NRF_ERROR_INVALID_PARAM;
    }

    memset(&hvx_params, 0, sizeof(hvx_params));

    hvx_params.handle = p_gfp->tx_handles.value_handle;
    hvx_params.p_data = p_data;
    hvx_params.p_len  = p_length;
    hvx_params.type   = BLE_GATT_HVX_NOTIFICATION;

    return sd_ble_gatts_hvx(conn_handle, &hvx_params);
}

#endif

