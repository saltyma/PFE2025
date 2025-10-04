#include "stm32u5xx_hal.h"
#include "cmox_crypto.h"
#include "cmox_ecdsa.h"
#include "ecc/cmox_ecc.h"
//#include "stm32u5xx_hal_crc.h"
//#include "stm32u5xx_hal_rcc.h"
#include <string.h>
#include <stdio.h>

cmox_ecc_handle_t Ecc_Ctx;
uint8_t Working_Buffer[2000];  // Buffer de travail
uint32_t Computed_Random[8];   // Buffer random matériel RNG
extern RNG_HandleTypeDef hrng;

void Crypto_Init(void)
{
    cmox_init_arg_t init_target = {CMOX_INIT_TARGET_AUTO, NULL};
    if (cmox_initialize(&init_target) != CMOX_INIT_SUCCESS)
    {
        printf("Erreur initialisation Cryptolib\n");
        while(1);
    }
}

int Generate_ECC_Key(uint8_t *privKey, size_t privKeyLen,
                     uint8_t *pubKey, size_t *pubKeyLen)
{
    // Not supported as direct call here, generate key elsewhere or with other API
    // Adapt selon besoin, exemple officiel ne montre pas génération directe
    return -1;
}

int Sign_Message(const uint8_t *privKey, size_t privKeyLen,
                 const uint8_t *msg, size_t msgLen,
                 uint8_t *signature, size_t *signatureLen)
{
    cmox_hash_retval_t hStatus;
    cmox_ecc_retval_t eStatus;
    size_t computed_size;
    uint8_t hash[CMOX_SHA224_SIZE];

    // Hash du message
    hStatus = cmox_hash_compute(CMOX_SHA224_ALGO, msg, msgLen, hash, sizeof(hash), &computed_size);
    if (hStatus != CMOX_HASH_SUCCESS) return -1;

    // Construct context
    cmox_ecc_construct(&Ecc_Ctx, CMOX_ECC256_MATH_FUNCS, Working_Buffer, sizeof(Working_Buffer));

    // Génération d'un vrai random matériel (simulateur ici)
    for (uint32_t i = 0; i < sizeof(Computed_Random)/sizeof(uint32_t); i++)
    {
        if (HAL_RNG_GenerateRandomNumber(&hrng, &Computed_Random[i]) != HAL_OK)
        {
            return -1;
        }
    }

    // Signature
    eStatus = cmox_ecdsa_sign(&Ecc_Ctx,
                              CMOX_ECC_CURVE_SECP256R1,
                              (uint8_t *)Computed_Random, sizeof(Computed_Random),
                              privKey, privKeyLen,
                              hash, computed_size,
                              signature, signatureLen);

    cmox_ecc_cleanup(&Ecc_Ctx);
    return (eStatus == CMOX_ECC_SUCCESS) ? 0 : -1;
}

int Verify_Signature(const uint8_t *pubKey, size_t pubKeyLen,
                     const uint8_t *msg, size_t msgLen,
                     const uint8_t *signature, size_t signatureLen)
{
    cmox_hash_retval_t statusHash;
    cmox_ecc_retval_t statusEcc;
    size_t computed_size;
    uint8_t hash[CMOX_SHA224_SIZE];
    uint32_t faultCheck = CMOX_ECC_AUTH_FAIL;

    // Hash du message
    statusHash = cmox_hash_compute(CMOX_SHA224_ALGO, msg, msgLen, hash, sizeof(hash), &computed_size);
    if (statusHash != CMOX_HASH_SUCCESS) return -1;

    // Construct context
    cmox_ecc_construct(&Ecc_Ctx, CMOX_ECC256_MATH_FUNCS, Working_Buffer, sizeof(Working_Buffer));

    // Vérification signature
    statusEcc = cmox_ecdsa_verify(&Ecc_Ctx,
                                  CMOX_ECC_CURVE_SECP256R1,
                                  pubKey, pubKeyLen,
                                  hash, computed_size,
                                  signature, signatureLen,
                                  &faultCheck);

    cmox_ecc_cleanup(&Ecc_Ctx);

    if ((statusEcc == CMOX_ECC_AUTH_SUCCESS) && (faultCheck == CMOX_ECC_AUTH_SUCCESS))
    {
        return 0;
    }
    else
        return -1;
}

int try_it(void)
{
    //HAL_Init();

    // Initialisation RNG hardware
    //hrng.Instance = RNG;
//    hrng.Init.ClockErrorDetection = RNG_CED_ENABLE;
//    if (HAL_RNG_Init(&hrng) != HAL_OK)
//    {
//        printf("Erreur init RNG\n");
//        return -1;
//    }

    Crypto_Init();

    uint8_t privKey[CMOX_ECC_SECP256R1_PRIVKEY_LEN] = { /* remplissage de la clé privée */ };
    uint8_t pubKey[CMOX_ECC_SECP256R1_PUBKEY_LEN] = { /* remplissage de la clé publique */ };
    size_t pubKeyLen = sizeof(pubKey);
    uint8_t signature[CMOX_ECC_SECP256R1_SIG_LEN];
    size_t signatureLen = sizeof(signature);
    const char *message = "STM32U585 PKA Demo";
    // Génération des clés
     if (Generate_ECC_Key(privKey, sizeof(privKey), pubKey, &pubKeyLen) == 0)
            printf("Clés ECC générées\n");

      else
            printf("Erreur génération clés\n");
    if (Sign_Message(privKey, sizeof(privKey), (const uint8_t *)message, strlen(message), signature, &signatureLen) == 0)
        //printf("Message signé\n");
        my_debug_marker(10); //clignote 5fois
    else
        printf("Erreur signature\n");

    if (Verify_Signature(pubKey, pubKeyLen, (const uint8_t *)message, strlen(message), signature, signatureLen) == 0)
        ////printf("Signature valide\n");
    my_debug_marker(20); //clignote 10fois
    else
        //printf("Signature invalide\n");
    	my_debug_marker(30);

    //while(1);
    return 0;
}
