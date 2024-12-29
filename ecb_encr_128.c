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

void string_to_aes_text(size_t text_len, const char *input, uint8_t *text) {
    size_t input_len = strlen(input);
    
    //printf("%d %d\n", text_len, input_len);
    
    // Если строка короче ключа, заполняем оставшиеся байты нулями
    if (input_len < text_len) {
        memcpy(text, input, input_len);
        memset(text + input_len, 0, text_len - input_len);
    } else {
        memcpy(text, input, text_len); // Если строка длиннее ключа, обрезаем её
    }
    //printf("%02x\n", input);
    //printf("%02x\n", text);
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
    printf("\n================================\n");
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

    //text_len = 64;
    
//----------
    char name_file[256]; //файл из которого шифруем
    char input[key_len]; // ключ
    char c;
    char flag = '0';

    FILE *buffer = fopen("buffer_temp.txt", "r");
    
    for (i = 0; i < key_len; i++){
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
    for (i = 0; i < 256; i++){
        c = fgetc(buffer);
        if (c == EOF){
            //for(j = i; j < key_length; j++)
            //    name_file[j]=' ';
            //name_file[key_length-1] = '\0';
            name_file[i] = '\0';
            break;
        }
        else 
            name_file[i] = c;
    }
    fclose(buffer);
    input[strcspn(input, "\n")] = '\0';

    string_to_aes_key(input, user_key, key_len); // ключ в  utf8

	PLAINTEXT = (uint8_t*)malloc(LENGTH); 
    CIPHERTEXT = (uint8_t*)malloc(LENGTH); 
    DECRYPTEDTEXT = (uint8_t*)malloc(LENGTH); 

    CIPHER_KEY = user_key;
    //PLAINTEXT = user_text;
	AES_set_encrypt_key(CIPHER_KEY, key_length, &key); 
    AES_set_decrypt_key(CIPHER_KEY, key_length, &decrypt_key); 

    flag = '0';
    char text[LENGTH]; // Для ввода теекста (максимум 64 символа + нулевой байт)
	FILE *buffer2 = fopen(name_file, "r");
	FILE *buffer3 = fopen("encrypt.txt", "w");

 	printf("++++++++++++++++++++++++++++++++++\n");
    while (flag=='0'){
	    /*
	    for (i = 0; i < text_len-1; i++){
	        c = fgetc(buffer2);
	        if (c == EOF){
                text[i] = '\0';
                //for(j = i+1; j < text_len; j++)
                //    text[j]='0';
                flag='1';
	            break;
	        }
	        else 
	            text[i] = c;
	    }
	    if (flag == '0')
	    	text[text_len-1]="\0";
	  	*/
	  	for (i = 0; i < LENGTH; i++){
	        c = fgetc(buffer2);
	        if (c == EOF){
                PLAINTEXT[i] = '\0';
                for(j = i+1; j < LENGTH; j++)
                    PLAINTEXT[j]=0;
                flag='1';
	            break;
	        }
	        else 
	            PLAINTEXT[i] =c;
	    	
	    	//printf("%c", PLAINTEXT[i]);
	    }

	    
	    //string_to_aes_text(text_len, text, user_text);
	    ////////////
	    /*
	    size_t input_len = strlen(text);
	    if (input_len < text_len) {// Если строка короче ключа, заполняем оставшиеся байты нулями
	        memcpy(user_text, text, input_len);
	        memset(user_text + input_len, 0, text_len - input_len);
	    } else {
	        //memcpy(user_text, text, 64); // Если строка длиннее ключа, обрезаем её
	        user_text = ()text;
	    }
	    */
	    ////////////	
	 
	    //PLAINTEXT = user_text;
	    //printf("%s\n%s\n\n", text, PLAINTEXT);
	    
	    //printf("+%s+\n", PLAINTEXT);
	    AES_ECB_encrypt(PLAINTEXT,  // шифрование текста
	                    CIPHERTEXT, 
	                    LENGTH, 
	                    key.KEY, 
	                    key.nr); 
	    for (i = 0; i < LENGTH; i++){
            //printf("%s", forSwitch);
	    	//fprintf(buffer3, "%c", (__m128i*)CIPHERTEXT[i]);
            fprintf(buffer3, "%02x", (__m128i*)CIPHERTEXT[i]);
	        //printf("%02x ", (__m128i*)CIPHERTEXT[i]);   
        }
        printf("\n");
	    //fputs(CIPHERTEXT, buffer3);
 	}
 	printf("++++++++++++++++++++++++++++++++++\n");
 	fclose(buffer2);
 	fclose(buffer3);
 	
    printf("\n=====Text has been encrypt.=====\n");
}


