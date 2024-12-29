//AES_CBC_decrypt (const unsigned char *in,  
//                 unsigned char *out, 
//                 unsigned char ivec[16], 
//                 unsigned long length, 
//                 const unsigned char *KS, 
//                 int nr) 
 
.globl AES_CBC_decrypt 
AES_CBC_decrypt: 
# parameter 1: %rdi 
# parameter 2: %rsi 
# parameter 3: %rdx 
# parameter 4: %rcx 
# parameter 5: %r8 
# parameter 6: %r9d 
 
        movq      %rcx, %r10 
        shrq   $4, %rcx 
        shlq      $60, %r10 
        je    DNO_PARTS_4 
        addq      $1, %rcx 
DNO_PARTS_4: 
        movq      %rcx, %r10 
        shlq      $62, %r10 
        shrq      $62, %r10 
        shrq      $2, %rcx 
        movdqu    (%rdx),%xmm5 
        je        DREMAINDER_4 
        subq      $64, %rsi 
DLOOP_4: 
        movdqu    (%rdi), %xmm1                                  
        movdqu    16(%rdi), %xmm2                                
        movdqu    32(%rdi), %xmm3                                
        movdqu    48(%rdi), %xmm4   
        movdqa    %xmm1, %xmm6                              
        movdqa    %xmm2, %xmm7                              
        movdqa    %xmm3, %xmm8                              
        movdqa    %xmm4, %xmm15                              
        movdqa    (%r8), %xmm9                                  
        movdqa    16(%r8), %xmm10                               
        movdqa    32(%r8), %xmm11                               
        movdqa    48(%r8), %xmm12                               
        pxor      %xmm9, %xmm1                                   
        pxor      %xmm9, %xmm2                                   
        pxor      %xmm9, %xmm3                                   
        pxor      %xmm9, %xmm4                                   
        aesdec    %xmm10, %xmm1                                  
        aesdec    %xmm10, %xmm2                                  
        aesdec    %xmm10, %xmm3                                  
        aesdec    %xmm10, %xmm4                                  
        aesdec    %xmm11, %xmm1                                  
        aesdec    %xmm11, %xmm2                                  
        aesdec    %xmm11, %xmm3                                  
        aesdec    %xmm11, %xmm4                                  
        aesdec    %xmm12, %xmm1                                  
        aesdec    %xmm12, %xmm2                                  
        aesdec    %xmm12, %xmm3                                  
        aesdec    %xmm12, %xmm4                                  
        movdqa    64(%r8), %xmm9                                
        movdqa    80(%r8), %xmm10                               
        movdqa    96(%r8), %xmm11                               
        movdqa    112(%r8), %xmm12                              
        aesdec    %xmm9, %xmm1                                   
        aesdec    %xmm9, %xmm2                                   
        aesdec    %xmm9, %xmm3                                   
        aesdec    %xmm9, %xmm4                                   
        aesdec    %xmm10, %xmm1                                  
        aesdec    %xmm10, %xmm2                                  
        aesdec    %xmm10, %xmm3 
	aesdec    %xmm10, %xmm4                                  
        aesdec    %xmm11, %xmm1                                  
        aesdec    %xmm11, %xmm2                                  
        aesdec    %xmm11, %xmm3                                  
        aesdec    %xmm11, %xmm4                                  
        aesdec    %xmm12, %xmm1                                  
        aesdec    %xmm12, %xmm2                                  
        aesdec    %xmm12, %xmm3                                  
        aesdec    %xmm12, %xmm4                                  
        movdqa    128(%r8), %xmm9                               
        movdqa    144(%r8), %xmm10                              
        movdqa    160(%r8), %xmm11                                  
        cmpl      $12, %r9d                                
        aesdec    %xmm9, %xmm1                                   
        aesdec    %xmm9, %xmm2                                   
        aesdec    %xmm9, %xmm3                                   
        aesdec    %xmm9, %xmm4                                   
        aesdec    %xmm10, %xmm1                                  
        aesdec    %xmm10, %xmm2                                  
        aesdec    %xmm10, %xmm3                                  
        aesdec    %xmm10, %xmm4                                    
        jb        DLAST_4 
        movdqa    160(%r8), %xmm9                               
        movdqa    176(%r8), %xmm10                              
        movdqa    192(%r8), %xmm11                                  
        cmpl      $14, %r9d                                
        aesdec    %xmm9, %xmm1                                   
        aesdec    %xmm9, %xmm2                                   
        aesdec    %xmm9, %xmm3                                   
        aesdec    %xmm9, %xmm4                                   
        aesdec    %xmm10, %xmm1                                  
        aesdec    %xmm10, %xmm2                                  
        aesdec    %xmm10, %xmm3                                  
        aesdec    %xmm10, %xmm4                                    
        jb        DLAST_4 
        movdqa    192(%r8), %xmm9                               
        movdqa    208(%r8), %xmm10                              
        movdqa    224(%r8), %xmm11                              
        aesdec    %xmm9, %xmm1                                   
        aesdec    %xmm9, %xmm2                                   
        aesdec    %xmm9, %xmm3                                   
        aesdec    %xmm9, %xmm4                                   
        aesdec    %xmm10, %xmm1                                  
        aesdec    %xmm10, %xmm2                                  
        aesdec    %xmm10, %xmm3                                  
        aesdec    %xmm10, %xmm4                                  
DLAST_4: 
        addq      $64, %rdi                                      
        addq      $64, %rsi                                      
        decq      %rcx                                           
        aesdeclast %xmm11, %xmm1                                 
        aesdeclast %xmm11, %xmm2                                 
        aesdeclast %xmm11, %xmm3                                 
        aesdeclast %xmm11, %xmm4     
        pxor   %xmm5 ,%xmm1                             
        pxor   %xmm6 ,%xmm2                             
        pxor   %xmm7 ,%xmm3                             
        pxor   %xmm8 ,%xmm4                             
        movdqu    %xmm1, (%rsi)                                  
        movdqu    %xmm2, 16(%rsi)  
	 movdqu    %xmm3, 32(%rsi)                                
        movdqu    %xmm4, 48(%rsi)    
        movdqa    %xmm15,%xmm5                             
        jne       DLOOP_4 
        addq      $64, %rsi                                      
DREMAINDER_4: 
        cmpq      $0, %r10                                       
        je        DEND_4 
DLOOP_4_2: 
        movdqu    (%rdi), %xmm1   
        movdqa    %xmm1 ,%xmm15                                
        addq      $16, %rdi                                      
        pxor      (%r8), %xmm1                                  
        movdqu    160(%r8), %xmm2                              
        cmpl      $12, %r9d                                  
        aesdec    16(%r8), %xmm1                                
        aesdec    32(%r8), %xmm1                                
        aesdec    48(%r8), %xmm1                                
        aesdec    64(%r8), %xmm1                                
        aesdec    80(%r8), %xmm1                                
        aesdec    96(%r8), %xmm1                                
        aesdec    112(%r8), %xmm1                               
        aesdec    128(%r8), %xmm1                               
        aesdec    144(%r8), %xmm1                                    
        jb        DLAST_4_2 
        movdqu    192(%r8), %xmm2                             
        cmpl      $14, %r9d                                    
        aesdec    160(%r8), %xmm1                               
        aesdec    176(%r8), %xmm1                                   
        jb        DLAST_4_2 
        movdqu    224(%r8), %xmm2                               
        aesdec    192(%r8), %xmm1                               
        aesdec    208(%r8), %xmm1                               
DLAST_4_2: 
        aesdeclast %xmm2, %xmm1   
        pxor      %xmm5, %xmm1 
        movdqa    %xmm15, %xmm5                                
        movdqu    %xmm1, (%rsi)                                  
        addq      $16, %rsi                                      
        decq      %r10                                           
        jne       DLOOP_4_2 
DEND_4: 
        ret

//AES_CBC_encrypt (const unsigned char *in,  
//                 unsigned char *out, 
//                 unsigned char ivec[16], 
//                 unsigned long length, 
//                 const unsigned char *KS, 
//                 int nr) 
 
.globl AES_CBC_encrypt 
AES_CBC_encrypt: 
# parameter 1: %rdi 
# parameter 2: %rsi 
# parameter 3: %rdx 
# parameter 4: %rcx 
# parameter 5: %r8 
# parameter 6: %r9d 
 
        movq      %rcx, %r10 
        shrq      $4, %rcx 
        shlq      $60, %r10 
        je        NO_PARTS 
        addq      $1, %rcx 
NO_PARTS: 
        subq      $16, %rsi 
        movdqa    (%rdx), %xmm1 
LOOP: 
        pxor      (%rdi), %xmm1 
        pxor      (%r8),  %xmm1 
        addq      $16,%rsi 
        addq      $16,%rdi 
        cmpl      $12, %r9d  
        aesenc    16(%r8),%xmm1 
        aesenc    32(%r8),%xmm1 
        aesenc    48(%r8),%xmm1 
        aesenc    64(%r8),%xmm1 
        aesenc    80(%r8),%xmm1 
        aesenc    96(%r8),%xmm1 
        aesenc    112(%r8),%xmm1 
        aesenc    128(%r8),%xmm1 
        aesenc    144(%r8),%xmm1 
        movdqa    160(%r8),%xmm2 
        jb        LAST 
        cmpl      $14, %r9d 
        aesenc    160(%r8),%xmm1 
        aesenc    176(%r8),%xmm1 
        movdqa    192(%r8),%xmm2 
        jb        LAST 
        aesenc    192(%r8),%xmm1 
        aesenc    208(%r8),%xmm1 
        movdqa    224(%r8),%xmm2 
LAST: 
        decq       %rcx 
        aesenclast %xmm2,%xmm1 
        movdqu     %xmm1,(%rsi) 
         
        jne        LOOP 
        ret

