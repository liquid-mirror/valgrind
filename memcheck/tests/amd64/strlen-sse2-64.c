
#include <stdio.h>
#include <stdlib.h>

/* This is the version that is in glibc cvs */

asm(
".text"            "\n\t"
".globl __strlen_sse2\n\t"
".type __strlen_sse2, @function\n\t"
"__strlen_sse2:"                          "\n\t"
""                                        "\n\t"
"        movq    %rdi, %rcx"              "\n\t"
"        movq    %rdi, %r8"               "\n\t"
"        andq    $~15, %rdi"              "\n\t"
"        pxor    %xmm1, %xmm1"            "\n\t"
"        orl     $0xffffffff, %esi"       "\n\t"
"        movdqa  (%rdi), %xmm0"           "\n\t"
"        subq    %rdi, %rcx"              "\n\t"
"        leaq    16(%rdi), %rdi"          "\n\t"
"        pcmpeqb %xmm1, %xmm0"            "\n\t"
"        shl     %cl, %esi"               "\n\t"
"        pmovmskb %xmm0, %edx"            "\n\t"
"        xorl    %eax, %eax"              "\n\t"
"        negq    %r8"                     "\n\t"
"        andl    %esi, %edx"              "\n\t"
"        jnz     1f"                      "\n\t"
""                                        "\n\t"
"2:      movdqa  (%rdi), %xmm0"           "\n\t"
"        leaq    16(%rdi), %rdi"          "\n\t"
"        pcmpeqb %xmm1, %xmm0"            "\n\t"
"        pmovmskb %xmm0, %edx"            "\n\t"
"        testl   %edx, %edx"              "\n\t"
"        jz      2b"                      "\n\t"
""                                        "\n\t"
"1:      leaq    -16(%rdi,%r8), %rdi"     "\n\t"
"        bsfl    %edx, %eax"              "\n\t"
"        addq    %rdi, %rax"              "\n\t"
"        ret"                             "\n\t"
""                                        "\n\t"
".size __strlen_sse2, .-__strlen_sse2"    "\n\t"
".previous\n"
);

extern int __strlen_sse2 ( char* );

int main ( void )
{
  int i;
  char* str = malloc(4);
  str[0] = str[1] = 'x';
  str[2] = 0;
  printf("len is %d\n", __strlen_sse2(str));
  free(str);

  str = malloc(12);
  for (i = 0; i < 12-2; i++)
    str[i] = 'y';
  str[i] = 0;
  printf("len is %d\n", __strlen_sse2(str));
  free(str);

  return 0;
}
