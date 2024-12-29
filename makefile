program_encript: ecb_decr_128_exe ecb_encr_128_exe
	gcc -o encrypt_interface encrypt_interface.c `pkg-config --cflags --libs gtk+-3.0`
ecb_encr_128_exe: ecb_encr_128.c key_expansion.o aes.c Check_CPU_support_AES.c
	gcc -maes -msse4 ecb_encr_128.c ecb.o key_expansion.o aes.c Check_CPU_support_AES.c -DHAVE_VPRINTF  -D AES128 -o ecb_encr_128_exe
#ecb_exe: ecb_main.c ecb.o key_expansion.o aes.c Check_CPU_support_AES.c
#	gcc -maes -msse4 ecb_main.c ecb.o key_expansion.o aes.c Check_CPU_support_AES.c -DHAVE_VPRINTF  -D AES128 -o ecb_exe
ecb_decr_128_exe: ecb_decr_128.c key_expansion.o aes.c Check_CPU_support_AES.c
	gcc -maes -msse4 ecb_decr_128.c ecb.o key_expansion.o aes.c Check_CPU_support_AES.c -DHAVE_VPRINTF  -D AES128 -o ecb_decr_128_exe	
ecb.o: ecb.s
	gcc -maes -msse4  -nostartfiles -c ecb.s -o ecb.o
key_expansion.o: key_expansion.s	
	gcc -maes -msse4  -nostartfiles -c key_expansion.s -o key_expansion.o

