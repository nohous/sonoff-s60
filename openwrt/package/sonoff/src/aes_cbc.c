/*
 * aes_cbc.so - ucode module for AES-128-CBC + MD5
 * Wraps mbedtls for Sonoff device communication
 *
 * Build: mipsel-linux-gnu-gcc -shared -fPIC -O2 -o aes_cbc.so aes_cbc.c \
 *        -I/path/to/ucode/include -lmbedcrypto
 */

#include <string.h>
#include <stdlib.h>

#include <ucode/module.h>
#include <ucode/types.h>

#include <mbedtls/aes.h>
#include <mbedtls/md5.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

/* Base64 encoding table */
static const char b64_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* Base64 encode */
static char *b64_encode(const unsigned char *data, size_t len, size_t *out_len)
{
    size_t olen = 4 * ((len + 2) / 3);
    char *out = malloc(olen + 1);
    if (!out) return NULL;

    size_t i, j;
    for (i = 0, j = 0; i < len; i += 3, j += 4) {
        uint32_t n = ((uint32_t)data[i]) << 16;
        if (i + 1 < len) n |= ((uint32_t)data[i + 1]) << 8;
        if (i + 2 < len) n |= data[i + 2];

        out[j]     = b64_table[(n >> 18) & 0x3F];
        out[j + 1] = b64_table[(n >> 12) & 0x3F];
        out[j + 2] = (i + 1 < len) ? b64_table[(n >> 6) & 0x3F] : '=';
        out[j + 3] = (i + 2 < len) ? b64_table[n & 0x3F] : '=';
    }
    out[olen] = '\0';
    *out_len = olen;
    return out;
}

/* Base64 decode */
static unsigned char *b64_decode(const char *data, size_t len, size_t *out_len)
{
    if (len % 4 != 0) return NULL;

    size_t olen = len / 4 * 3;
    if (len > 0 && data[len - 1] == '=') olen--;
    if (len > 1 && data[len - 2] == '=') olen--;

    unsigned char *out = malloc(olen);
    if (!out) return NULL;

    static const unsigned char d[] = {
        255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
        255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
        255,255,255,255,255,255,255,255,255,255,255, 62,255,255,255, 63,
         52, 53, 54, 55, 56, 57, 58, 59, 60, 61,255,255,255,  0,255,255,
        255,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
         15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,255,255,255,255,255,
        255, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
         41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51,255,255,255,255,255
    };

    size_t i, j;
    for (i = 0, j = 0; i < len; i += 4, j += 3) {
        uint32_t n = (d[(unsigned char)data[i]] << 18) |
                     (d[(unsigned char)data[i + 1]] << 12) |
                     (d[(unsigned char)data[i + 2]] << 6) |
                     d[(unsigned char)data[i + 3]];
        if (j < olen) out[j] = (n >> 16) & 0xFF;
        if (j + 1 < olen) out[j + 1] = (n >> 8) & 0xFF;
        if (j + 2 < olen) out[j + 2] = n & 0xFF;
    }
    *out_len = olen;
    return out;
}

/* PKCS7 padding */
static size_t pkcs7_pad(unsigned char *data, size_t len, size_t block_size)
{
    size_t pad_len = block_size - (len % block_size);
    for (size_t i = 0; i < pad_len; i++) {
        data[len + i] = (unsigned char)pad_len;
    }
    return len + pad_len;
}

/* PKCS7 unpadding - returns new length or 0 on error */
static size_t pkcs7_unpad(unsigned char *data, size_t len)
{
    if (len == 0) return 0;
    unsigned char pad = data[len - 1];
    if (pad == 0 || pad > 16) return 0;
    for (size_t i = 0; i < pad; i++) {
        if (data[len - 1 - i] != pad) return 0;
    }
    return len - pad;
}

/*
 * encrypt(plaintext, key_string) -> { iv: base64, data: base64 }
 *
 * Key is MD5(key_string), IV is random 16 bytes
 */
static uc_value_t *
uc_aes_encrypt(uc_vm_t *vm, size_t nargs)
{
    uc_value_t *plain_arg = uc_fn_arg(0);
    uc_value_t *key_arg = uc_fn_arg(1);

    if (ucv_type(plain_arg) != UC_STRING || ucv_type(key_arg) != UC_STRING) {
        return NULL;
    }

    const char *plaintext = ucv_string_get(plain_arg);
    size_t plain_len = ucv_string_length(plain_arg);
    const char *key_str = ucv_string_get(key_arg);
    size_t key_len = ucv_string_length(key_arg);

    /* Derive key: MD5(key_string) */
    unsigned char key[16];
    mbedtls_md5((const unsigned char *)key_str, key_len, key);

    /* Generate random IV */
    unsigned char iv[16];
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);
    mbedtls_ctr_drbg_random(&ctr_drbg, iv, 16);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    /* Allocate buffer for padded plaintext */
    size_t padded_len = ((plain_len / 16) + 1) * 16;
    unsigned char *padded = malloc(padded_len);
    if (!padded) return NULL;

    memcpy(padded, plaintext, plain_len);
    padded_len = pkcs7_pad(padded, plain_len, 16);

    /* Encrypt */
    unsigned char iv_copy[16];
    memcpy(iv_copy, iv, 16);  /* mbedtls modifies IV in-place */

    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_enc(&aes, key, 128);
    mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, padded_len, iv_copy, padded, padded);
    mbedtls_aes_free(&aes);

    /* Base64 encode results */
    size_t iv_b64_len, data_b64_len;
    char *iv_b64 = b64_encode(iv, 16, &iv_b64_len);
    char *data_b64 = b64_encode(padded, padded_len, &data_b64_len);
    free(padded);

    if (!iv_b64 || !data_b64) {
        free(iv_b64);
        free(data_b64);
        return NULL;
    }

    /* Build result object */
    uc_value_t *result = ucv_object_new(vm);
    ucv_object_add(result, "iv", ucv_string_new(iv_b64));
    ucv_object_add(result, "data", ucv_string_new(data_b64));

    free(iv_b64);
    free(data_b64);

    return result;
}

/*
 * decrypt(iv_base64, data_base64, key_string) -> plaintext string
 */
static uc_value_t *
uc_aes_decrypt(uc_vm_t *vm, size_t nargs)
{
    uc_value_t *iv_arg = uc_fn_arg(0);
    uc_value_t *data_arg = uc_fn_arg(1);
    uc_value_t *key_arg = uc_fn_arg(2);

    if (ucv_type(iv_arg) != UC_STRING ||
        ucv_type(data_arg) != UC_STRING ||
        ucv_type(key_arg) != UC_STRING) {
        return NULL;
    }

    const char *iv_b64 = ucv_string_get(iv_arg);
    size_t iv_b64_len = ucv_string_length(iv_arg);
    const char *data_b64 = ucv_string_get(data_arg);
    size_t data_b64_len = ucv_string_length(data_arg);
    const char *key_str = ucv_string_get(key_arg);
    size_t key_len = ucv_string_length(key_arg);

    /* Derive key: MD5(key_string) */
    unsigned char key[16];
    mbedtls_md5((const unsigned char *)key_str, key_len, key);

    /* Decode base64 */
    size_t iv_len, data_len;
    unsigned char *iv = b64_decode(iv_b64, iv_b64_len, &iv_len);
    unsigned char *data = b64_decode(data_b64, data_b64_len, &data_len);

    if (!iv || !data || iv_len != 16 || data_len % 16 != 0) {
        free(iv);
        free(data);
        return NULL;
    }

    /* Decrypt */
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_dec(&aes, key, 128);
    mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, data_len, iv, data, data);
    mbedtls_aes_free(&aes);
    free(iv);

    /* Remove PKCS7 padding */
    size_t plain_len = pkcs7_unpad(data, data_len);
    if (plain_len == 0) {
        free(data);
        return NULL;
    }

    uc_value_t *result = ucv_string_new_length((char *)data, plain_len);
    free(data);

    return result;
}

/*
 * md5(string) -> hex string
 */
static uc_value_t *
uc_md5(uc_vm_t *vm, size_t nargs)
{
    uc_value_t *arg = uc_fn_arg(0);
    if (ucv_type(arg) != UC_STRING) return NULL;

    const char *data = ucv_string_get(arg);
    size_t len = ucv_string_length(arg);

    unsigned char hash[16];
    mbedtls_md5((const unsigned char *)data, len, hash);

    char hex[33];
    for (int i = 0; i < 16; i++) {
        sprintf(hex + i*2, "%02x", hash[i]);
    }

    return ucv_string_new(hex);
}

/*
 * b64encode(string) -> base64 string
 */
static uc_value_t *
uc_b64encode(uc_vm_t *vm, size_t nargs)
{
    uc_value_t *arg = uc_fn_arg(0);
    if (ucv_type(arg) != UC_STRING) return NULL;

    const char *data = ucv_string_get(arg);
    size_t len = ucv_string_length(arg);

    size_t out_len;
    char *b64 = b64_encode((const unsigned char *)data, len, &out_len);
    if (!b64) return NULL;

    uc_value_t *result = ucv_string_new(b64);
    free(b64);
    return result;
}

/*
 * b64decode(base64_string) -> decoded string
 */
static uc_value_t *
uc_b64decode(uc_vm_t *vm, size_t nargs)
{
    uc_value_t *arg = uc_fn_arg(0);
    if (ucv_type(arg) != UC_STRING) return NULL;

    const char *data = ucv_string_get(arg);
    size_t len = ucv_string_length(arg);

    size_t out_len;
    unsigned char *decoded = b64_decode(data, len, &out_len);
    if (!decoded) return NULL;

    uc_value_t *result = ucv_string_new_length((char *)decoded, out_len);
    free(decoded);
    return result;
}

/* Function table */
static const uc_function_list_t aes_fns[] = {
    { "encrypt",   uc_aes_encrypt },
    { "decrypt",   uc_aes_decrypt },
    { "md5",       uc_md5 },
    { "b64encode", uc_b64encode },
    { "b64decode", uc_b64decode },
};

void uc_module_init(uc_vm_t *vm, uc_value_t *scope)
{
    uc_function_list_register(scope, aes_fns);
}
