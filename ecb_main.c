//#define AES128 
//#define AES192 
//#define AES256 
#ifndef LENGTH 
#define LENGTH 64 
#endif 
 
#include <stdint.h> 
#include <stdio.h> 
#include <wmmintrin.h>
#include <string.h>
#include <ctype.h> 
#include <stdlib.h> 

#if !defined (ALIGN16) 
# if defined (__GNUC__) 
#  define ALIGN16  __attribute__((aligned(16))) 
# else 
#  define ALIGN16 __declspec (align (16)) 
# endif 
#endif 

extern  int Check_CPU_support_AES();

typedef struct KEY_SCHEDULE{ 
    ALIGN16 unsigned char KEY[16*15]; 
    unsigned int nr; 
    } AES_KEY; 

extern int AES_set_encrypt_key(const unsigned char *userKey, const int bits, AES_KEY *key);
extern int AES_set_decrypt_key(const unsigned char *userKey, const int bits, AES_KEY *key);
extern void AES_ECB_encrypt(const unsigned char *in, unsigned char *out, unsigned long length, 
const unsigned char*KS, int nr);
extern void AES_ECB_decrypt(const unsigned char *in,  
unsigned char *out, unsigned long length, const unsigned char *KS, int nr);
extern void AES_128_Key_Expansion(const unsigned char *userkey, 
                            unsigned char *key);
extern void AES_192_Key_Expansion(const unsigned char *userkey, 
                            unsigned char *key);
extern void AES_256_Key_Expansion(const unsigned char *userkey, 
                            unsigned char *key);

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

void string_to_aes_key(const char *input, uint8_t *key, size_t key_len) {
    size_t input_len = strlen(input);

    // Если строка короче ключа, заполняем оставшиеся байты нулями
    if (input_len < key_len) {
        memcpy(key, input, input_len);
        memset(key + input_len, 0, key_len - input_len);
    } else {
        memcpy(key, input, key_len); // Если строка длиннее ключа, обрезаем её
    }
}

void string_to_aes_text(const char *input, uint8_t *text, size_t text_len) {
    size_t input_len = strlen(input);

    // Если строка короче ключа, заполняем оставшиеся байты нулями
    if (input_len < text_len) {
        memcpy(text, input, input_len);
        memset(text + input_len, 0, text_len - input_len);
    } else {
        memcpy(text, input, text_len); // Если строка длиннее ключа, обрезаем её
    }
}


/*****************************************************************************/ 

int main(){
    AES_KEY key;
    AES_KEY decrypt_key;
    uint8_t *PLAINTEXT;
    uint8_t *CIPHERTEXT;
    uint8_t *DECRYPTEDTEXT;
    /*uint8_t *EXPECTED_CIPHERTEXT;*/
    uint8_t *CIPHER_KEY;
    int i,j;
    int key_length;
    uint8_t user_key[32]; // Максимальный размер для 256-битного ключа
    uint8_t user_text[32];
    size_t key_len;
    size_t text_len;

    if (!Check_CPU_support_AES()){
        printf("Cpu does not support AES instruction set. Bailing out.\n");
        return 1;
        }
    printf("CPU support AES instruction set.\n\n");

#ifdef AES128
#define STR "Performing AES128 ECB.\n"
    /*EXPECTED_CIPHERTEXT = ECB128_EXPECTED;*/
    key_length = 128;
    key_len = 16;
    printf("Ожидается 16 байт (32 символа)!\n");
#elif defined AES192
#define STR "Performing AES192 ECB.\n"
    CIPHER_KEY = AES192_TEST_KEY;
    /*EXPECTED_CIPHERTEXT = ECB192_EXPECTED;*/
    key_length = 192;
    key_len = 24;
    printf("Ожидается 24 байта (48 символов)!\n");
#elif defined AES256
#define STR "Performing AES256 ECB.\n" 
    CIPHER_KEY = AES256_TEST_KEY; 
    /*EXPECTED_CIPHERTEXT = ECB256_EXPECTED; */
    key_length = 256; 
    key_len = 32;
     printf("Ожидается 32 байта (64 символа)!\n");
#endif

    text_len = 32;
    
//----------
    char name_file[256]; //файл из которого шифруем
    char input[key_length]; // ключ
    char c;
    char flag = '0';
    FILE *buffer = fopen("buffer_temp.txt", "r");
    
    for (i = 0; i < key_length; i++){
        c = fgetc(buffer);
        input[i] = c;
        if (c == '\n'){
            flag = '1';
            break;
        }
    }
    if (flag=='0') {
        while ((c = fgetc(buffer)) != '\n')
            continue;
    }
    for (i = 0; i < key_length; i++){
        c = fgetc(buffer);
        if (c == EOF){
            name_file[i] = '\0';
            break;
        }
        else 
            name_file[i] = c;
    }
    fclose(buffer);
    input[strcspn(input, "\n")] = '\0';
    //printf("%s \n%s \n", input, name_file);

    char text[text_len]; // Для ввода теекста (максимум 64 символа + нулевой байт)
    FILE *buffer2 = fopen(name_file, "r");
    for (i = 0; i < text_len; i++){
        c = fgetc(buffer2);
        if (c == EOF){
            text[i] = '\0';
            break;
        }
        else 
            text[i] = c;
    }
    fclose(buffer2);
    //printf("%s \n", text);
    //----------



    /*char input[256]; // Для ввода ключа (максимум 64 символа + нулевой байт)
    
    if (!fgets(input, sizeof(input), stdin)) {
        printf("Ошибка ввода.\n");
        return 1;
    }

    input[strcspn(input, "\n")] = '\0';
    */
    string_to_aes_key(input, user_key, key_len);

    printf("Ключ успешно создан из строки:\n");
    for (size_t i = 0; i < key_len; i++) {
        printf("%02x", user_key[i]);
    }
    printf("\n");

    /*char text[256]; // Для ввода теекста (максимум 64 символа + нулевой байт)
    printf("Ожидается 32 байта (64 символа) для ввода текста!\n");
    if (!fgets(text, sizeof(text), stdin)) {
        printf("Ошибка ввода.\n");
        return 1;
    }
    text[strcspn(text, "\n")] = '\0';
    */
    string_to_aes_text(text, user_text, text_len);
    
    printf("Текст успешно создан из строки:\n");
    for (size_t i = 0; i < text_len; i++) {
        printf("%02x", user_text[i]);
    }
    printf("\n");

    //////////////////////////////////////////////////////////////////////



    PLAINTEXT = (uint8_t*)malloc(LENGTH); 
    CIPHERTEXT = (uint8_t*)malloc(LENGTH); 
    DECRYPTEDTEXT = (uint8_t*)malloc(LENGTH); 

    CIPHER_KEY = user_key;
    PLAINTEXT = user_text;
     

    AES_set_encrypt_key(CIPHER_KEY, key_length, &key); 
    AES_set_decrypt_key(CIPHER_KEY, key_length, &decrypt_key); 
 
    AES_ECB_encrypt(PLAINTEXT,  // шифрование текста
                    CIPHERTEXT, 
                    LENGTH, 
                    key.KEY, 
                    key.nr); 
 
    AES_ECB_decrypt(CIPHERTEXT, // дешифрование текста
                    DECRYPTEDTEXT, 
                    LENGTH, 
                    decrypt_key.KEY, 
                    decrypt_key.nr); 
 
    printf("%s\n",STR); 
    printf("The Cipher Key:\n"); 
    print_m128i_with_string("",((__m128i*)CIPHER_KEY)[0]); 
    if (key_length > 128) 
      print_m128i_with_string_short("",((__m128i*)CIPHER_KEY)[1],(key_length/8) -16); 

    for (i = 0; i < key_len; i++)
    {
        printf("%x , ", user_key[i]);
    }
    printf("\n");
    
 
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

    /*for(i=0; i<LENGTH; i++){
        if (CIPHERTEXT[i] != EXPECTED_CIPHERTEXT[i%(16*4)]){
          printf("The CIPHERTEXT is not equal to the EXPECTED CIHERTEXT.\n\n");
          return 1;
          }
        }
    printf("The CIPHERTEXT equals to the EXPECTED CIHERTEXT.\n\n");
    */
    /*for(i=0; i<LENGTH; i++){
        if (DECRYPTEDTEXT[i] != PLAINTEXT[i%(16*4)]){
            printf("The DECRYPTED TEXT isn't equal to the original PLAINTEXT!");
            printf("\n\n");
            return 1;
            }
        }*/
    //printf("The DECRYPTED TEXT equals to the original PLAINTEXT.\n\n");
    printf("Введенный текст:    %s\n", text);
    /*printf("Зашифрованный текст:  ");
    for (size_t i = 0; i < LENGTH; i++) {
        printf("%c", CIPHERTEXT[i]);
        
    } */
    printf("Расшифрованный текст:  ");
    for (size_t i = 0; i < text_len; i++) {
        printf("%c", DECRYPTEDTEXT[i]);
    }

    FILE *buffer3 = fopen("encrypt.txt", "w");
    fputs(CIPHERTEXT, buffer3);
    fclose(buffer3);
    printf("\n");
    }
