
#include <stdio.h>
#include <stdlib.h>

asm(
".text"            "\n\t"
".globl __strlen_sse2\n\t"
".type __strlen_sse2, @function\n\t"
"__strlen_sse2:         "   "\n\t"
                           "\n\t"
"       pushl   %ebp"                       "\n\t"
"       movl    %esp, %ebp"                 "\n\t"
"	mov	8(%esp), %eax"              "\n\t"
"	mov	%eax, %ecx"                 "\n\t"
"	pxor	%xmm0, %xmm0"               "\n\t"
"	mov	%eax, %esi"                 "\n\t"
"	and	$15, %ecx"                  "\n\t"
"	jz	1f"                         "\n\t"
""                                          "\n\t"
"	and	$-16, %esi"                 "\n\t"
""                                          "\n\t"
"	pcmpeqb	(%esi), %xmm0"              "\n\t"
"	lea	16(%eax), %esi"             "\n\t"
"	pmovmskb %xmm0, %edx"               "\n\t"
""                                          "\n\t"
"	shr	%cl, %edx"                  "\n\t"
"	test	%edx, %edx"                 "\n\t"
"	jnz	2f"                         "\n\t"
"	sub	%ecx, %esi"                 "\n\t"
"	pxor	%xmm0, %xmm0"               "\n\t"
""                                          "\n\t"
"1:"                                        "\n\t"
"	pcmpeqb	(%esi), %xmm0"              "\n\t"
"	pmovmskb %xmm0, %edx"               "\n\t"
""                                          "\n\t"
"	add	$16, %esi"                  "\n\t"
"	test	%edx, %edx"                 "\n\t"
"	jnz	2f"                         "\n\t"
""                                          "\n\t"
"	pcmpeqb	(%esi), %xmm0"              "\n\t"
"	pmovmskb %xmm0, %edx"               "\n\t"
"	add	$16, %esi"                  "\n\t"
"	test	%edx, %edx"                 "\n\t"
"	jnz	2f"                         "\n\t"
""                                          "\n\t"
"	pcmpeqb	(%esi), %xmm0"              "\n\t"
"	pmovmskb %xmm0, %edx"               "\n\t"
"	add	$16, %esi"                  "\n\t"
"	test	%edx, %edx"                 "\n\t"
"	jnz	2f"                         "\n\t"
""                                          "\n\t"
"	pcmpeqb	(%esi), %xmm0"              "\n\t"
"	pmovmskb %xmm0, %edx"               "\n\t"
"	add	$16, %esi"                  "\n\t"
"	test	%edx, %edx"                 "\n\t"
"	jz	1b"                         "\n\t"
""                                          "\n\t"
"2:"                                        "\n\t"
"	neg	%eax"                       "\n\t"
"	lea	-16(%eax, %esi), %eax"      "\n\t"
"	bsf	%edx, %ecx"                 "\n\t"
"	add	%ecx, %eax"                 "\n\t"
"       leave"                              "\n\t"
"	ret"                                "\n\t"
".size __strlen_sse2, .-__strlen_sse2"      "\n\t"
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
