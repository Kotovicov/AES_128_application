#ifndef LENGTH 
#define LENGTH 64 
#endif

#include <stdint.h>
#include <stdio.h>
#include <wmmintrin.h>

#if !defined (ALIGN16)
# if defined (__GNUC__)
#  define ALIGN16  __attribute__  ( (aligned (16)))
# else
#  define ALIGN16 __declspec (align (16))
# endif
#endif

typedef struct KEY_SCHEDULE{
    ALIGN16 unsigned char KEY[16*15];
    unsigned int nr;
    }AES_KEY;

/*test vectors were taken from http://w3.antd.nist.gov/iip_pubs/rfc3602.txt*/

ALIGN16 uint8_t AES128_TEST_KEY[] = {0x7E,0x24,0x06,0x78,0x17,0xFA,0xE0,0xD7,
                                     0x43,0xD6,0xCE,0x1F,0x32,0x53,0x91,0x63};

ALIGN16 uint8_t AES192_TEST_KEY[] = {0x7C,0x5C,0xB2,0x40,0x1B,0x3D,0xC3,0x3C,
                                     0x19,0xE7,0x34,0x08,0x19,0xE0,0xF6,0x9C,
                                     0x67,0x8C,0x3D,0xB8,0xE6,0xF6,0xA9,0x1A};
ALIGN16 uint8_t AES256_TEST_KEY[] = {0xF6,0xD6,0x6D,0x6B,0xD5,0x2D,0x59,0xBB,
                                     0x07,0x96,0x36,0x58,0x79,0xEF,0xF8,0x86,
                                     0xC6,0x6D,0xD5,0x1A,0x5B,0x6A,0x99,0x74,
                                     0x4B,0x50,0x59,0x0C,0x87,0xA2,0x38,0x84};

ALIGN16 uint8_t AES_TEST_VECTOR[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                                     0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,
                                     0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
                                     0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F};

ALIGN16 uint8_t CTR128_IV[] = {0xC0,0x54,0x3B,0x59,0xDA,0x48,0xD9,0x0B};
ALIGN16 uint8_t CTR192_IV[] = {0x02,0x0C,0x6E,0xAD,0xC2,0xCB,0x50,0x0D};
ALIGN16 uint8_t CTR256_IV[] = {0xC1,0x58,0x5E,0xF1,0x5A,0x43,0xD8,0x75};

ALIGN16 uint8_t CTR128_NONCE[] = {0x00,0x6C,0xB6,0xDB};
ALIGN16 uint8_t CTR192_NONCE[] = {0x00,0x96,0xB0,0x3B};
ALIGN16 uint8_t CTR256_NONCE[] = {0x00,0xFA,0xAC,0x24};

ALIGN16 uint8_t CTR128_EXPECTED[] = {0x51,0x04,0xA1,0x06,0x16,0x8A,0x72,0xD9,
                                     0x79,0x0D,0x41,0xEE,0x8E,0xDA,0xD3,0x88,
                                     0xEB,0x2E,0x1E,0xFC,0x46,0xDA,0x57,0xC8,
                                     0xFC,0xE6,0x30,0xDF,0x91,0x41,0xBE,0x28};

ALIGN16 uint8_t CTR192_EXPECTED[] = {0x45,0x32,0x43,0xFC,0x60,0x9B,0x23,0x32,
                                     0x7E,0xDF,0xAA,0xFA,0x71,0x31,0xCD,0x9F,
                                     0x84,0x90,0x70,0x1C,0x5A,0xD4,0xA7,0x9C,
                                     0xFC,0x1F,0xE0,0xFF,0x42,0xF4,0xFB,0x00};

ALIGN16 uint8_t CTR256_EXPECTED[] = {0xF0,0x5E,0x23,0x1B,0x38,0x94,0x61,0x2C,
                                     0x49,0xEE,0x00,0x0B,0x80,0x4E,0xB2,0xA9,
                                     0xB8,0x30,0x6B,0x50,0x8F,0x83,0x9D,0x6A,
				     0x55,0x30,0x83,0x1D,0x93,0x44,0xAF,0x1C};
/*****************************************************************************/
void print_m128i_with_string(char* string,__m128i data)
    {
    unsigned char *pointer = (unsigned char*)&data;
    int i;
    printf("%-40s[0x",string);
    for (i=0; i<16; i++)
        printf("%02x",pointer[i]);
    printf("]\n");
    }
void print_m128i_with_string_short(char* string,__m128i data,int length)
    {
    unsigned char *pointer = (unsigned char*)&data;
    int i;
    printf("%-40s[0x",string);
    for (i=0; i<length; i++)
        printf("%02x",pointer[i]);
    printf("]\n");
    }
/*****************************************************************************/
int main(){
    AES_KEY key;
    uint8_t *PLAINTEXT;
    uint8_t *CIPHERTEXT;
    uint8_t *DECRYPTEDTEXT;
    uint8_t *EXPECTED_CIPHERTEXT;
    uint8_t *CIPHER_KEY;
    uint8_t *NONCE;
    uint8_t *IV;
    int i,j;
    int key_length;

    if (!Check_CPU_support_AES()){
        printf("Cpu does not support AES instruction set. Bailing out.\n");
        return 1;
        }
    printf("CPU support AES instruction set.\n\n");


#ifdef AES128
#define STR "Performing AES128 CTR.\n"
    CIPHER_KEY = AES128_TEST_KEY;
    EXPECTED_CIPHERTEXT = CTR128_EXPECTED;
    IV = CTR128_IV;
    NONCE = CTR128_NONCE;
    key_length = 128;
#elif defined AES192
#define STR "Performing AES192 CTR.\n"
    CIPHER_KEY = AES192_TEST_KEY;
    EXPECTED_CIPHERTEXT = CTR192_EXPECTED;
    IV = CTR192_IV;
    NONCE = CTR192_NONCE;
    key_length = 192;
#elif defined AES256
#define STR "Performing AES256 CTR.\n"
    CIPHER_KEY = AES256_TEST_KEY;
    EXPECTED_CIPHERTEXT = CTR256_EXPECTED;
    IV = CTR256_IV;
    NONCE = CTR256_NONCE;
    key_length = 256;
#endif

    PLAINTEXT = (uint8_t*)malloc(LENGTH);
    CIPHERTEXT = (uint8_t*)malloc(LENGTH);
    DECRYPTEDTEXT = (uint8_t*)malloc(LENGTH);

    for(i=0 ;i<LENGTH/16/2; i++){
        for(j=0; j<2; j++){
            _mm_storeu_si128(&((__m128i*)PLAINTEXT)[i*2+j],
                              ((__m128i*)AES_TEST_VECTOR)[j]);
            }
        }
    for(j=i*2 ; j<LENGTH/16; j++){
        _mm_storeu_si128(&((__m128i*)PLAINTEXT)[j],
                          ((__m128i*)AES_TEST_VECTOR)[j%4]);
        }
    if (LENGTH%16){
        _mm_storeu_si128(&((__m128i*)PLAINTEXT)[j],
                          ((__m128i*)AES_TEST_VECTOR)[j%4]);
        }

    AES_set_encrypt_key(CIPHER_KEY, key_length, &key);

    AES_CTR_encrypt(PLAINTEXT,
                    CIPHERTEXT,
                    IV,
                    NONCE,
                    LENGTH,
                    key.KEY,
                    key.nr);

    AES_CTR_encrypt(CIPHERTEXT,
                    DECRYPTEDTEXT,
                    IV,
                    NONCE,
                    LENGTH,
                    key.KEY,
                    key.nr);

    printf("%s\n",STR);
    printf("The Cipher Key:\n");
    print_m128i_with_string("",((__m128i*)CIPHER_KEY)[0]);
    if (key_length > 128)
      print_m128i_with_string_short("",((__m128i*)CIPHER_KEY)[1],(key_length/8) -16);

    printf("The Key Schedule:\n");
    for (i=0; i< key.nr; i++)
        print_m128i_with_string("",((__m128i*)key.KEY)[i]);

    printf("The PLAINTEXT:\n");
    for (i=0; i< LENGTH/16; i++)
        print_m128i_with_string("",((__m128i*)PLAINTEXT)[i]);
    if (LENGTH%16)
        print_m128i_with_string_short("",((__m128i*)PLAINTEXT)[i],LENGTH%16);
    printf("\n\nThe CIPHERTEXT:\n");
    for (i=0; i< LENGTH/16; i++)
        print_m128i_with_string("",((__m128i*)CIPHERTEXT)[i]);
    if (LENGTH%16)
        print_m128i_with_string_short("",((__m128i*)CIPHERTEXT)[i],LENGTH%16);
    for(i=0; i< ((32<LENGTH)? 32 : LENGTH); i++){
        if (CIPHERTEXT[i] != EXPECTED_CIPHERTEXT[i%(16*2)]){
            printf("The ciphertext is not equal to the expected ciphertext.\n\n");
            return 1;
            }
        }
    printf("The CIPHERTEXT equals to the EXPECTED CIHERTEXT"
           " for bytes where expected text was entered.\n\n");
    for(i=0; i<LENGTH; i++){
        if (DECRYPTEDTEXT[i] != PLAINTEXT[i]){
            printf("The DECRYPTED TEXT is not equal to the original"
                   "PLAINTEXT.\n\n");
            return 1;
            }
        }
    printf("The DECRYPTED TEXT equals to the original PLAINTEXT.\n\n");
    }
