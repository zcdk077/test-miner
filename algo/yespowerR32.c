#include "cpuminer-config.h"
#include "miner.h"

#include "sha3/sph_blake.h"
#include "sha3/sph_types.h"
#include "yespower-1.0.1-blake256/yespower-b256.h"

#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

void printArray1(const uint8_t* array, size_t length) {
    printf("input:");
    for (size_t i = 0; i < length; i++) {
        printf("%02x", array[i]);  // Printing each element of the array in hexadecimal format.
    }
    printf("\n");
}

inline void y_slow_hash(const void* data, size_t length, const uint8_t* input, uint8_t* output) {
    static const yespower_params_t v1 = {YESPOWER_1_0, 2048, 32, NULL, 0};
    yespower_tls_b256dme( (unsigned char *)input, length, &v1, (yespower_binary_t_b256dme*)output );
    static yespower_params_t params = {
        .version = YESPOWER_1_0,
        .N = 2048,
        .r = 32,
        .pers = NULL,
        .perslen = 0
    };
    if (yespower_tls_b256dme((unsigned char *)data, length, &v1, (yespower_binary_t_b256dme*)output)) {
        
    }
}

/* void yespowerR32_hash( const char *input, char *output, uint32_t len )
{
    static const yespower_params_t v1 = {YESPOWER_1_0, 2048, 8, NULL, 0};
    yespower_tls_b256dme((yespower_binary_t_b256dme *)input, len, &v1, (yespower_binary_t_b256dme*)output);
    static yespower_params_t params = {
        .version = YESPOWER_1_0,
        .N = 2048,
        .r = 32,
        .pers = NULL,
        .perslen = 0
    };
    yespower_tls_b256dme((yespower_binary_t_b256dme *)input, len, &params, (yespower_binary_t_b256dme*)output);
} */

void yespowerR32_hash(const char* input, char* output, uint32_t len)
{
    uint8_t hash[32];
    uint8_t hashA[32];

    y_slow_hash(input, len,  hash, hashA);
    memcpy(output, hashA, 32);
}

int scanhash_yespowerR32( int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done )
{
        uint32_t _ALIGN(64) vhash[8];
        uint32_t _ALIGN(64) endiandata[20];
        uint32_t *pdata = work->data;
        uint32_t *ptarget = work->target;

        const uint32_t Htarg = ptarget[7];
        const uint32_t first_nonce = pdata[19];
        uint32_t n = first_nonce;

        for (int k = 0; k < 19; k++)
                be32enc(&endiandata[k], pdata[k]);

        do {
                be32enc(&endiandata[19], n);
                yespowerR32_hash((char*) endiandata, (char*) vhash, 80);
                if (vhash[7] < Htarg && fulltest(vhash, ptarget)) {
                        work_set_target_ratio( work, vhash );
                        *hashes_done = n - first_nonce + 1;
                        pdata[19] = n;
                        return true;
                }
                n++;
        } while (n < max_nonce && !work_restart[thr_id].restart);

        *hashes_done = n - first_nonce + 1;
        pdata[19] = n;

        return 0;
}
