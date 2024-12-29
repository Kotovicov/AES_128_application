.align    16 
ONE: 
.quad 0x00000000,0x00000001  
.align    16 
FOUR: 
.quad 0x00000004,0x00000004 
.align    16 
EIGHT: 
.quad 0x00000008,0x00000008 
.align    16 
TWO_N_ONE: 
.quad 0x00000002,0x00000001 
.align    16 
TWO_N_TWO: 
.quad 0x00000002,0x00000002 
.align    16 
LOAD_HIGH_BROADCAST_AND_BSWAP: 
.byte 15,14,13,12,11,10,9,8,15,14,13,12,11,10,9,8 
.align    16 
BSWAP_EPI_64: 
.byte 7,6,5,4,3,2,1,0,15,14,13,12,11,10,9,8 
 
//AES_CTR_encrypt (const unsigned char *in,  
//                 unsigned char *out, 
//                 const unsigned char ivec[8], 
//                 const unsigned char nonce[4], 
//                 unsigned long length, 
//                 const unsigned char *key, 
 //                 int nr) 
 
.globl AES_CTR_encrypt 
 
AES_CTR_encrypt: 
# parameter 1: %rdi 
# parameter 2: %rsi 
# parameter 3: %rdx 
# parameter 4: %rcx 
# parameter 5: %r8 
# parameter 6: %r9 
# parameter 7: 8 + %rsp 
 
        movq      %r8, %r10 
        movl      8(%rsp), %r12d 
        shrq      $4, %r8 
        shlq      $60, %r10 
        je          NO_PARTS_4 
        addq      $1, %r8 
NO_PARTS_4: 
        movq      %r8, %r10 
        shlq      $62, %r10 
        shrq      $62, %r10               
         
        pinsrq    $1, (%rdx), %xmm0 
        pinsrd    $1, (%rcx), %xmm0 
        psrldq    $4, %xmm0 
        movdqa    %xmm0, %xmm2 
        pshufb    (LOAD_HIGH_BROADCAST_AND_BSWAP), %xmm2 
        paddq     (TWO_N_ONE), %xmm2 
        movdqa    %xmm2, %xmm1 
        paddq     (TWO_N_TWO), %xmm2 
        pshufb    (BSWAP_EPI_64), %xmm1       
        pshufb    (BSWAP_EPI_64), %xmm2  
         
        shrq      $2, %r8 
        je        REMAINDER_4 
        subq      $64, %rsi         
        subq      $64, %rdi           
LOOP_4:
	 addq      $64, %rsi         
        addq      $64, %rdi   
         
        movdqa    %xmm0, %xmm11 
        movdqa    %xmm0, %xmm12 
        movdqa    %xmm0, %xmm13 
        movdqa    %xmm0, %xmm14 
         
        shufpd    $2, %xmm1, %xmm11 
        shufpd    $0, %xmm1, %xmm12 
        shufpd    $2, %xmm2, %xmm13 
        shufpd    $0, %xmm2, %xmm14 
         
        pshufb    (BSWAP_EPI_64), %xmm1 
        pshufb    (BSWAP_EPI_64), %xmm2 
         
        movdqa      (%r9), %xmm8 
        movdqa      16(%r9), %xmm9 
        movdqa      32(%r9), %xmm10 
        movdqa      48(%r9), %xmm7 
         
        paddq     (FOUR), %xmm1 
        paddq     (FOUR), %xmm2 
         
        pxor      %xmm8, %xmm11 
        pxor      %xmm8, %xmm12 
        pxor      %xmm8, %xmm13 
        pxor      %xmm8, %xmm14 
         
        pshufb    (BSWAP_EPI_64), %xmm1 
        pshufb    (BSWAP_EPI_64), %xmm2 
         
        aesenc    %xmm9, %xmm11 
        aesenc    %xmm9, %xmm12 
        aesenc    %xmm9, %xmm13 
        aesenc    %xmm9, %xmm14 
        aesenc    %xmm10, %xmm11 
        aesenc    %xmm10, %xmm12 
        aesenc    %xmm10, %xmm13 
        aesenc    %xmm10, %xmm14 
        aesenc    %xmm7, %xmm11 
        aesenc    %xmm7, %xmm12 
        aesenc    %xmm7, %xmm13 
        aesenc    %xmm7, %xmm14         
         
        movdqa      64(%r9), %xmm8 
        movdqa      80(%r9), %xmm9 
        movdqa      96(%r9), %xmm10 
        movdqa      112(%r9), %xmm7 
         
        aesenc    %xmm8, %xmm11 
        aesenc    %xmm8, %xmm12 
        aesenc    %xmm8, %xmm13 
        aesenc    %xmm8, %xmm14 
        aesenc    %xmm9, %xmm11 
        aesenc    %xmm9, %xmm12 
        aesenc    %xmm9, %xmm13 
        aesenc    %xmm9, %xmm14 
        aesenc    %xmm10, %xmm11 
        aesenc    %xmm10, %xmm12
	 aesenc    %xmm10, %xmm13 
        aesenc    %xmm10, %xmm14 
        aesenc    %xmm7, %xmm11 
        aesenc    %xmm7, %xmm12 
        aesenc    %xmm7, %xmm13 
        aesenc    %xmm7, %xmm14 
         
        movdqa      128(%r9), %xmm8 
        movdqa      144(%r9), %xmm9 
        movdqa      160(%r9), %xmm10         
        cmp          $12, %r12d 
         
        aesenc    %xmm8, %xmm11 
        aesenc    %xmm8, %xmm12 
        aesenc    %xmm8, %xmm13 
        aesenc    %xmm8, %xmm14 
        aesenc    %xmm9, %xmm11 
        aesenc    %xmm9, %xmm12 
        aesenc    %xmm9, %xmm13 
        aesenc    %xmm9, %xmm14 
        jb          LAST_4 
        movdqa      160(%r9), %xmm8 
        movdqa      176(%r9), %xmm9 
        movdqa      192(%r9), %xmm10 
        cmp          $14, %r12d 
         
        aesenc    %xmm8, %xmm11 
        aesenc    %xmm8, %xmm12 
        aesenc    %xmm8, %xmm13 
        aesenc    %xmm8, %xmm14 
        aesenc    %xmm9, %xmm11 
        aesenc    %xmm9, %xmm12 
        aesenc    %xmm9, %xmm13 
        aesenc    %xmm9, %xmm14 
        jb          LAST_4 
        
        movdqa      192(%r9), %xmm8 
        movdqa      208(%r9), %xmm9 
        movdqa      224(%r9), %xmm10 
         
        aesenc    %xmm8, %xmm11 
        aesenc    %xmm8, %xmm12 
        aesenc    %xmm8, %xmm13 
        aesenc    %xmm8, %xmm14 
        aesenc    %xmm9, %xmm11 
        aesenc    %xmm9, %xmm12 
        aesenc    %xmm9, %xmm13 
        aesenc    %xmm9, %xmm14 
LAST_4: 
         
        aesenclast %xmm10, %xmm11      
        aesenclast %xmm10, %xmm12      
        aesenclast %xmm10, %xmm13      
        aesenclast %xmm10, %xmm14 
         
        pxor    (%rdi), %xmm11      
        pxor    16(%rdi), %xmm12      
        pxor    32(%rdi), %xmm13      
        pxor    48(%rdi), %xmm14
	movdqu  %xmm11, (%rsi)     
        movdqu  %xmm12, 16(%rsi)     
        movdqu  %xmm13, 32(%rsi)     
        movdqu  %xmm14, 48(%rsi) 
        dec %r8     
        jne LOOP_4 
         
        addq  $64,%rsi 
        addq  $64,%rdi 
         
REMAINDER_4: 
        cmp $0, %r10 
        je END_4 
        shufpd  $2, %xmm1, %xmm0 
IN_LOOP_4: 
        movdqa %xmm0, %xmm11 
        pshufb (BSWAP_EPI_64), %xmm0 
        pxor   (%r9), %xmm11 
        paddq  (ONE), %xmm0 
        aesenc 16(%r9), %xmm11 
        aesenc 32(%r9), %xmm11 
        pshufb (BSWAP_EPI_64), %xmm0 
        aesenc 48(%r9), %xmm11 
        aesenc 64(%r9), %xmm11 
        aesenc 80(%r9), %xmm11 
        aesenc 96(%r9), %xmm11 
        aesenc 112(%r9), %xmm11 
        aesenc 128(%r9), %xmm11 
        aesenc 144(%r9), %xmm11 
        movdqa 160(%r9), %xmm2 
        cmp       $12, %r12d 
        jb     IN_LAST_4 
        aesenc 160(%r9), %xmm11 
        aesenc 176(%r9), %xmm11 
        movdqa 192(%r9), %xmm2 
        cmp       $14, %r12d 
        jb     IN_LAST_4 
        aesenc 192(%r9), %xmm11 
        aesenc 208(%r9), %xmm11 
        movdqa 224(%r9), %xmm2 
IN_LAST_4: 
        aesenclast %xmm2, %xmm11 
        pxor       (%rdi) ,%xmm11 
        movdqu     %xmm11, (%rsi)         
        addq       $16,%rdi 
        addq       $16,%rsi 
        dec        %r10 
        jne        IN_LOOP_4             
END_4: 
        ret
