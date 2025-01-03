/*  
A function with OpenSSL interface (using AES_KEY struct), to call the other key
length specific key expansion functions 
*/ 
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
    } AES_KEY;

extern int AES_set_encrypt_key (const unsigned char *userKey,  
                         const int bits, 
                         AES_KEY *key);
extern int AES_set_decrypt_key (const unsigned char *userKey,  
                         const int bits, 
                         AES_KEY *key);
extern void AES_128_ENCRYPT_on_the_fly (const unsigned char *userkey, 
                                 const unsigned char *data);
extern void AES_128_Key_Expansion (const unsigned char *userkey, 
                            AES_KEY *key); 
extern void AES_192_Key_Expansion (const unsigned char *userkey, 
                            AES_KEY *key);
extern void AES_256_Key_Expansion (const unsigned char *userkey, 
                            AES_KEY *key); 




int AES_set_encrypt_key(const unsigned char *userKey,
                         const int bits,
                         AES_KEY *key)
    {
    if (!userKey || !key)
  	return -1;
 	if (bits == 128)
        {
        AES_128_Key_Expansion (userKey,key);
        key->nr = 10;
        return 0;
        }
    else if (bits == 192)
        {
        AES_192_Key_Expansion (userKey,key);
        key->nr = 12;
        return 0;
        }
    else if (bits == 256)
        {
        AES_256_Key_Expansion (userKey,key);
        key->nr = 14;
        return 0;
        }
    return -2;
    }

int AES_set_decrypt_key(const unsigned char *userKey,
                         const int bits,
                         AES_KEY *key)
    {
    int i,nr;;
    AES_KEY temp_key;
    __m128i *Key_Schedule = (__m128i*)key->KEY;
    __m128i *Temp_Key_Schedule = (__m128i*)temp_key.KEY;
    if (!userKey || !key)
  	return -1;

    if (AES_set_encrypt_key(userKey,bits,&temp_key) == -2)
        return -2;

    nr = temp_key.nr;
    key->nr = nr;

    Key_Schedule[nr] = Temp_Key_Schedule[0];
    Key_Schedule[nr-1] = _mm_aesimc_si128(Temp_Key_Schedule[1]);
    Key_Schedule[nr-2] = _mm_aesimc_si128(Temp_Key_Schedule[2]);
    Key_Schedule[nr-3] = _mm_aesimc_si128(Temp_Key_Schedule[3]);
    Key_Schedule[nr-4] = _mm_aesimc_si128(Temp_Key_Schedule[4]);
    Key_Schedule[nr-5] = _mm_aesimc_si128(Temp_Key_Schedule[5]);
    Key_Schedule[nr-6] = _mm_aesimc_si128(Temp_Key_Schedule[6]);
    Key_Schedule[nr-7] = _mm_aesimc_si128(Temp_Key_Schedule[7]);
    Key_Schedule[nr-8] = _mm_aesimc_si128(Temp_Key_Schedule[8]);
    Key_Schedule[nr-9] = _mm_aesimc_si128(Temp_Key_Schedule[9]);
    if(nr>10){
        Key_Schedule[nr-10] = _mm_aesimc_si128(Temp_Key_Schedule[10]);
        Key_Schedule[nr-11] = _mm_aesimc_si128(Temp_Key_Schedule[11]);
        }
    if(nr>12){
        Key_Schedule[nr-12] = _mm_aesimc_si128(Temp_Key_Schedule[12]);
        Key_Schedule[nr-13] = _mm_aesimc_si128(Temp_Key_Schedule[13]);
        }
    Key_Schedule[0] = Temp_Key_Schedule[nr];
    return 0;
    }
