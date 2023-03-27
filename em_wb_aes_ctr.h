/*
 * 본 프로그램에 대한 저작권을 포함한 지적재산권은 삼성SDS(주)에 있으며,
 * 삼성SDS(주)가 명시적으로 허용하지 않은 사용, 복사, 변경, 제3자에의 공개,
 * 배포는 엄격히 금지되며, 삼성SDS(주)의 지적재산권 침해에 해당됩니다.
 *
 * Copyright (c) 2016 Samsung SDS Co., Ltd. All Rights neserved. Confidential.
 *
 * All information including the intellectual and technical concepts contained
 * herein is, and remains the property of Samsung SDS Co. Ltd. Unauthorize une,
 * dissemination, or reproduction of this material is strictly forbidden unless
 * prior written permission is obtained from Samsung SDS Co. Ltd.
 */

#ifndef HEADER_EM_WB_AES_CTR_H
#define HEADER_EM_WB_AES_CTR_H

#if defined(__cplusplus)
extern "C" {
#endif

/* ---- swbc-attributes.h  ---- */
#if !defined(WIN32) && !defined(_WIN32)

/* macro for hidden symbol visibility */
#define SWBCINTERNAL __attribute__((visibility("hidden")))

/* macro for default symbol visibility */
#define SWBCEXPORT __attribute__((visibility("default")))

#else

/* macro for hidden symbol visibility */
#define SWBCINTERNAL

/* macro for default symbol visibility */
#define SWBCEXPORT

#endif
/* ---- end of swbc-attributes.h ----*/

/* ---- swbc-common.h ---- */
typedef enum { MODE_NOT_SET = 0, ENCRYPT_MODE, DECRYPT_MODE } SWBC_CIPHER_MODE;
/* ---- end of swbc-common.h ---- */

/* ---- swbc-aes.h ---- */
typedef unsigned int DWORD;
typedef unsigned char BYTE;

int SWBCINTERNAL SWBC_AES_set_key_encrypt(DWORD *rk, const BYTE *key);
int SWBCINTERNAL SWBC_AES_set_key_decrypt(DWORD *rk, const BYTE *key);
void SWBCINTERNAL SWBC_AES_encrypt(const unsigned char EncTable[16][256], const DWORD *rk, const BYTE *plaintext,
				   BYTE *ciphertext);
void SWBCINTERNAL SWBC_AES_decrypt(const unsigned char DecTable[16][256], const DWORD *rk, const BYTE *ciphertext,
				   BYTE *plaintext);

#define MUL2(a) (BYTE)(((a) << 1) ^ ((a)&0x80 ? 0x1b : 0))
#define MUL4(a) MUL2((MUL2(a)))
#define MUL8(a) MUL2((MUL2((MUL2(a)))))
#define MUL9(a) (MUL8(a) ^ (a))
#define MULB(a) (MUL8(a) ^ MUL2(a) ^ (a))
#define MULD(a) (MUL8(a) ^ MUL4(a) ^ (a))
#define MULE(a) (MUL8(a) ^ MUL4(a) ^ MUL2(a))

#define GETDWORD(plaintext)                                                                                            \
	(((DWORD)(plaintext)[0] << 24) ^ ((DWORD)(plaintext)[1] << 16) ^ ((DWORD)(plaintext)[2] << 8) ^                \
	 ((DWORD)(plaintext)[3]))

#define PUTDWORD(ciphertext, st)                                                                                       \
	{                                                                                                              \
		(ciphertext)[0] = (BYTE)((st) >> 24);                                                                  \
		(ciphertext)[1] = (BYTE)((st) >> 16);                                                                  \
		(ciphertext)[2] = (BYTE)((st) >> 8);                                                                   \
		(ciphertext)[3] = (BYTE)(st);                                                                          \
	}
/* ---- end of swbc-aes.h ---- */

/* ---- swbc-error.h ---- */
/**
 *
 *  ERROR NAME                            | ERROR CODES | ERROR Description
 *-----------------------------------------------------------------------------------------------------------------
 *  SWBC_SUCCESS                          |     0       |
 *  SWBC_FAILURE                          |     1       |
 *  SWBC_ERROR_PARAM_CTX_NULL             |     2       | "context parameter is NULL"
 *  SWBC_ERROR_PARAM_KEY_NULL             |     3       | "key parameter is NULL"
 *  SWBC_ERROR_PARAM_IV_NULL              |     4       | "iv parameter is NULL"
 *  SWBC_ERROR_PARAM_OUT_NULL             |     5       | "output parameter is NULL"
 *  SWBC_ERROR_PARAM_IN_NULL              |     6       | "input parameter is NULL"
 *  SWBC_ERROR_PARAM_IN_LENGTH_INVALID    |     7       | "input length parameter is invalid
 *  SWBC_ERROR_PARAM_OUT_LENGTH_NULL      |     8       | "output length parameter is NULL"
 *  SWBC_ERROR_FILE_OPEN_FAILED           |     9       | "file open failed"
 *  SWBC_ERROR_FILE_READ_FAILED           |     10      | "file read failed"
 *  SWBC_ERROR_RESOURCE_UNLOADED          |     11      | "swbc table unloaded"
 *  SWBC_ERROR_CIPHER_MODE_INVALID        |     12      | "cipher mode is invalid"
 */

/* structure for error codes */
typedef enum {
	SWBC_SUCCESS = 0,
	SWBC_FAILURE,
	SWBC_ERROR_PARAM_CTX_NULL,
	SWBC_ERROR_PARAM_KEY_NULL,
	SWBC_ERROR_PARAM_IV_NULL,
	SWBC_ERROR_PARAM_OUT_NULL,
	SWBC_ERROR_PARAM_IN_NULL,
	SWBC_ERROR_PARAM_IN_LENGTH_INVALID,
	SWBC_ERROR_PARAM_OUT_LENGTH_NULL,
	SWBC_ERROR_FILE_OPEN_FAILED,
	SWBC_ERROR_FILE_READ_FAILED,
	SWBC_ERROR_RESOURCE_UNLOADED,
	SWBC_ERROR_CIPHER_MODE_INVALID
} SWBC_ERROR;
/* ---- end of swbc-error.h ---- */

/* ---- swbc-utils.h ---- */
/**
 * Validates the SWBC tables
 *
 * swbc_table     SWBC table to be validated
 * tag            SWBC table tag to be used for validation
 *
 * returns SWBC_SUCCESS on success, other values on failure
 */
int SWBCINTERNAL table_check(const unsigned char **swbc_table, const unsigned char *tag);

/**
 * Sets the specified memory region with a value
 *
 * destination    memory region to be set
 * value          specific value to set the memory region
 * sizes          size of memory region in bytes
 *
 * returns void
 */
void SWBCINTERNAL memory_set(void *destination, const int value, unsigned int size);

/**
 * Copies the memory region from one to another
 *
 * destination    memory region to be copied to
 * source         memory region to be copied from
 * size           size of memory region of source in bytes
 *
 * returns void
 */
void SWBCINTERNAL memory_copy(void *destination, const void *source, unsigned int size);
/* ---- end of swbc-utils.h ---- */

/* ---- aes128-swbc-layer1-ctr.h ---- */
/* structure to hold wbc context information */
typedef struct {
	const unsigned char **swbc_table;
	unsigned int rc[44];
} aes128_swbc_layer1_ctr_ctx_t;

#define CTR_GET_OUTPUT_SIZE(input_size, mode)                                                                          \
	(((mode) == ENCRYPT_MODE || (mode) == DECRYPT_MODE) ? ((unsigned int)(input_size)) : 0)

/**
 * @brief
 * Loads SWBC table resource
 *
 * @param ctx         SWBC context
 * @param swbc_table  SWBC table resource
 * @param tag         tag for SWBC table resource. Tag is used to check whether the table resource is an appropriate one
 * or not
 *
 * @return SWBC_SUCCESS on success, other values on failure
 */
int SWBCEXPORT aes128_swbc_layer1_ctr_load(aes128_swbc_layer1_ctr_ctx_t *ctx, const unsigned char **swbc_table,
					   const unsigned char *tag);

/**
 * @brief
 * Initializes SWBC encryption context with specified key
 *
 * @param ctx         SWBC context
 * @param mc          SWBC initialization key
 *
 * @return SWBC_SUCCESS on success, other values on failure
 */
int SWBCEXPORT aes128_swbc_layer1_ctr_init(aes128_swbc_layer1_ctr_ctx_t *ctx, const unsigned char *mc);

/**
 * @brief
 * Encrypts data of arbitrary given length using SWBC encryption algorithm.
 * It uses ctr mode of operation.
 *
 * @param ctx         SWBC context
 * @param iv		      initialization vector
 * @param in          plaintext
 * @param out         storage for ciphertext(should be at least as large as given length)
 * @param len         plaintext length
 *
 * @return SWBC_SUCCESS on success, other values on failure
 */
int SWBCEXPORT aes128_swbc_layer1_ctr_encrypt(aes128_swbc_layer1_ctr_ctx_t *ctx, const unsigned char *iv,
					      const unsigned char *in, unsigned char *out, int len);

/**
 * @brief
 * Decrypts data of arbitrary given length using SWBC decryption algorithm.
 *
 * @param ctx         SWBC context
 * @param iv          initialization vector
 * @param in          ciphertext
 * @param out         storage for plaintext(should be at least as large as given length)
 * @param len         ciphertext length
 *
 * @return SWBC_SUCCESS on success, other values on failure
 */
int SWBCEXPORT aes128_swbc_layer1_ctr_decrypt(aes128_swbc_layer1_ctr_ctx_t *ctx, const unsigned char *iv,
					      const unsigned char *in, unsigned char *out, int len);
/* ---- end of aes128-swbc-layer1-ctr.h ---- */

#define EMWBEXPORT __attribute__((visibility("default")))

// Errono
#define EMWB_SUCCESS 0
#define EMWB_ERROR_INVALID_PT      -1000
#define EMWB_ERROR_INVALID_CT      -1001
#define EMWB_ERROR_INVALID_IV      -1002
#define EMWB_ERROR_CTX_NULL        -1003
#define EMWB_ERROR_LOAD_FAIL       -1004
#define EMWB_ERROR_INIT_FAIL       -1005
#define EMWB_ERROR_ENC_DEC_FAIL    -1006
#define EMWB_ERROR_INVALID_TAG     -1007

// WhiteBox TAG
#define EMWB_TAG_ETP               1
#define EMWB_TAG_TKN_DEL           2
/*
 * EM whitebox AES CTR Encryption
 * encrypt a plaintext of any size using aes ctr mode
 * pt: plaintext, pt_len: size of plaintext, ct: ciphertext, ct_len : size of ciphertext, iv: initialization vector
 * wb_tag : whitebox tag
 * @return EMWB_SUCCESS on success, other values on failure
 * @return ct_len on success
 */
int EMWBEXPORT em_wb_aes_ctr_encrypt(unsigned char *pt, unsigned int pt_len, unsigned char *ct, unsigned int *ct_len,
				     unsigned char *iv, int wb_tag);

/*
 * EM whitebox AES CTR Decryption
 * decrypt a ciphertext of any size using aes ctr mode
 * ct: ciphertext, ct_len : size of ciphertext, pt: plaintext, pt_len: size of plaintext, iv: initialization vector
 * wb_tag : whitebox tag
 * @return EMWB_SUCCESS on success, other values on failure
 * @return pt_len on success
 */
int EMWBEXPORT em_wb_aes_ctr_decrypt(unsigned char *ct, unsigned int ct_len, unsigned char *pt, unsigned int *pt_len,
				     unsigned char *iv, int wb_tag);

#if defined(__cplusplus)
}
#endif /*  __cplusplus */
#endif /*  HEADER_EM_WB_AES_CTR_H */
