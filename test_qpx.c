
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <malloc.h>
#include <setjmp.h>
#include <signal.h>
#include <string.h>

typedef  unsigned char           UChar;
typedef  unsigned int            UInt;
typedef  unsigned long int       UWord;
typedef  unsigned long long int  ULong;
typedef    signed long long int  Long;
typedef  double                  Double;

typedef  unsigned char           Bool;
#define False  ((Bool)0)
#define True   ((Bool)1)

#define IS_32_ALIGNED(_ptr) (0 == (0x1F & (UWord)(_ptr)))

typedef  union { UChar u8[32]; ULong u64[4]; Double f64[4]; }  QReg;

typedef
  struct { QReg q0; QReg q1; QReg q2; QReg q3; QReg q4; ULong i1; ULong i2; }
  Block;

// Options to be applied when printing results, in cases where V
// computes a more accurate result than the hardware.
//
// Show the number as-is.
#define OPT_NONE       0
// Mask off the least significant 41 bits before showing the number.
#define OPT_MASK_LO41  (1<<1)

void showQR ( QReg* qr, int options )
{
   int i;
   assert(IS_32_ALIGNED(qr));
   QReg copy = *qr;
   if (options & OPT_MASK_LO41) {
      // Masks off the low 41 bits
      const ULong mask = 0xFFFFFE0000000000ULL;
      for (i = 0; i < 4; i++)
         copy.u64[i] &= mask;
   }
   for (i = 0; i < 32; i++) {
      printf("%02x", (UInt)copy.u8[i]);
      if (i < 31 && 0 == ((i+1) & 7)) printf(".");
   }
}

void showBlock ( char* msg, Block* block, int options )
{
   printf("  %s\n", msg);
   printf("    "); showQR(&block->q0, options); printf("\n");
   printf("    "); showQR(&block->q1, options); printf("\n");
   printf("    "); showQR(&block->q2, options); printf("\n");
   printf("    "); showQR(&block->q3, options); printf("\n");
   printf("    "); showQR(&block->q4, options); printf("\n");
   printf("    %016llx %016llx\n", block->i1 & 0xFFFFFF,
                                   block->i2 & 0xFFFFFF);
}

UChar randUChar ( void )
{
   static UInt seed = 80021;
   seed = 1103515245 * seed + 12345;
   return (seed >> 17) & 0xFF;
}

ULong randULong ( void )
{
   int i;
   ULong n = 0;
   for (i = 0; i < 8; i++) {
      n <<= 8;
      n |= (ULong)(randUChar() & 0xFF);
   }
   return n;
}

// randDouble:
// Generate a random double-precision number.  About 1 time in 4,
// instead return a special value (+/- Inf, +/-Nan, denorm).
// This ensures that many of the groups of 4 calls here will
// return a special value.

static Double special_values[8];
static Bool   special_values_initted = False;

static __attribute__((noinline))
Double negate ( Double d ) { return -d; }
static __attribute__((noinline))
Double divf64 ( Double x, Double y ) { return x/y; }

static __attribute__((noinline))
Double plusZero  ( void ) { return 0.0; }
static __attribute__((noinline))
Double minusZero ( void ) { return negate(plusZero()); }

static __attribute__((noinline))
Double plusInf   ( void ) { return 1.0 / 0.0; }
static __attribute__((noinline))
Double minusInf  ( void ) { return negate(plusInf()); }

static __attribute__((noinline))
Double plusNaN  ( void ) { return divf64(plusInf(),plusInf()); }
static __attribute__((noinline))
Double minusNaN ( void ) { return negate(plusNaN()); }

static __attribute__((noinline))
Double plusDenorm  ( void ) { return 1.23e-315 / 1e3; }
static __attribute__((noinline))
Double minusDenorm ( void ) { return negate(plusDenorm()); }


static void ensure_special_values_initted ( void )
{
   if (special_values_initted) return;
   special_values[0] = plusZero();
   special_values[1] = minusZero();
   special_values[2] = plusInf();
   special_values[3] = minusInf();
   special_values[4] = plusNaN();
   special_values[5] = minusNaN();
   special_values[6] = plusDenorm();
   special_values[7] = minusDenorm();
   special_values_initted = True;
   int i;
   printf("\n");
   for (i = 0; i < 8; i++) {
      printf("special value %d = %e\n", i, special_values[i]);
   }
   printf("\n");
}

Double randDouble ( void )
{
   ensure_special_values_initted();
   UChar c = randUChar();
   if (c >= 64) {
      // return a normal number most of the time.
      // 0 .. 2^63-1
      ULong u64 = randULong();
      // -2^62 .. 2^62-1
      Long s64 = (Long)u64;
      // -2^55 .. 2^55-1
      s64 >>= (62-55);
      // and now as a float
      return (Double)s64;
   }
   c = randUChar() & 7;
   return special_values[c];
}

void randQReg_Double ( QReg* qr )
{
   qr->f64[0] = randDouble();
   qr->f64[1] = randDouble();
   qr->f64[2] = randDouble();
   qr->f64[3] = randDouble();
}

void randBlock ( Block* b )
{
   int i;
   UChar* p = (UChar*)b;
   for (i = 0; i < sizeof(Block); i++) {
      p[i] = randUChar();
   }
   randQReg_Double(&b->q0);
   randQReg_Double(&b->q1);
   randQReg_Double(&b->q2);
   randQReg_Double(&b->q3);
   randQReg_Double(&b->q4);
}

/* Generate a function test_NAME, that tests the given insn.  The the
   insn may mention as operands only QR6, QR7, QR8, QR9, R15 and R16,
   the latter two of which will be set safely to use as a 32-aligned,
   32-size memory operand (the sum points to Block::q2) */

static jmp_buf env_maybe_fpe;

static void handler_fpe ( int signo )
{
  longjmp(env_maybe_fpe, 1);
}

#define GEN_test(_name, _insn) \
   \
   __attribute__ ((noinline)) \
    static void test_##_name ( int options, int iterNo, int totIters ) \
   { \
     Block* b   = memalign(32, sizeof(Block)); \
     ULong  ea0 = (ULong)(&b->q2); \
     ULong  ea1 = randULong(); ea0 -= ea1; \
     assert(IS_32_ALIGNED(b)); \
     randBlock(b); \
     b->i1 = ea0; b->i2 = ea1; \
     printf("%s, test %d of %d \n", #_name, iterNo, totIters); \
     showBlock("before", b, OPT_NONE); \
     /* set up the SIGFPE handler */ \
     struct sigaction saved_sigfpe_act, tmp_sigfpe_act; \
     sigset_t saved_set, tmp_set; \
     memset(&saved_sigfpe_act, 0, sizeof(saved_sigfpe_act)); \
     memset(&tmp_sigfpe_act, 0, sizeof(tmp_sigfpe_act)); \
     memset(&saved_set, 0, sizeof(saved_set)); \
     memset(&tmp_set, 0, sizeof(tmp_set)); \
     /* Get the old sigaction */ \
     int r = sigaction(SIGFPE, NULL, &saved_sigfpe_act); \
     assert(r == 0); \
     /* Get the old sigmask, and install the new one. */ \
     sigemptyset(&tmp_set); \
     sigaddset(&tmp_set, SIGFPE); \
     r = sigprocmask(SIG_UNBLOCK, &tmp_set, &saved_set); \
     assert(r == 0); \
     /* Install the new handler. */ \
     tmp_sigfpe_act.sa_flags &= ~SA_RESETHAND; \
     tmp_sigfpe_act.sa_flags &= ~SA_SIGINFO; \
     tmp_sigfpe_act.sa_flags |=  SA_NODEFER; \
     tmp_sigfpe_act.sa_handler = handler_fpe; \
     r = sigaction(SIGFPE, &tmp_sigfpe_act, NULL); \
     assert(r == 0); \
     /* Now try the insn.  If it throws SIGFPE, catch it and continue. */ \
     if (setjmp(env_maybe_fpe)) { \
        printf("  caught SIGFPE (%s, %d of %d)\n", #_name, iterNo, totIters); \
     } else { \
       __asm__ __volatile__( \
       "mr        30, %0"                        "\n\t" \
       "li        29, 0"                         "\n\t" \
       "qvlfdxa   6,  30,29"  "; addi 30,30,32"  "\n\t" \
       "qvlfdxa   7,  30,29"  "; addi 30,30,32"  "\n\t" \
       /* skip ::q2 */        "; addi 30,30,32"  "\n\t" \
       "qvlfdxa   8,  30,29"  "; addi 30,30,32"  "\n\t" \
       "qvlfdxa   9,  30,29"  "; addi 30,30,32"  "\n\t" \
       "ldx       15, 30,29"  "; addi 30,30,8"   "\n\t" \
       "ldx       16, 30,29"                     "\n\t" \
       _insn                                     "\n\t" \
       "mr        30, %0"                        "\n\t" \
       "li        29, 0"                         "\n\t" \
       "qvstfdxa  6,  30,29"  "; addi 30,30,32"  "\n\t" \
       "qvstfdxa  7,  30,29"  "; addi 30,30,32"  "\n\t" \
       /* skip ::q2 */        "; addi 30,30,32"  "\n\t" \
       "qvstfdxa  8,  30,29"  "; addi 30,30,32"  "\n\t" \
       "qvstfdxa  9,  30,29"  "; addi 30,30,32"  "\n\t" \
       "stdx      15, 30,29"  "; addi 30,30,8"   "\n\t" \
       "stdx      16, 30,29"                     "\n\t" \
       : /*OUT*/   \
       : /*IN*/    "r"(b) \
       : /*TRASH*/ /*"qr6","qr7","qr8","qr9",*/ \
                   "fr6","fr7","fr8","fr9", \
                   "r15","r16","r30","r29","cc","memory" \
       ); \
     } \
     showBlock("after", b, options); \
     free(b); \
     /* Restore the original signal state. */ \
     r = sigaction(SIGFPE, &saved_sigfpe_act, NULL); \
     assert(r == 0); \
     r = sigprocmask(SIG_SETMASK, &saved_set, NULL); \
     assert(r == 0); \
  }

// Test load/store integration with legacy FP registers
GEN_test(LFD,    "add 15,15,16 ; lfd  7,0(15)")
GEN_test(LFS,    "add 15,15,16 ; lfs  7,0(15)")
GEN_test(LFDU,   "add 15,15,16 ; lfdu 7,0(15)")
GEN_test(LFSU,   "add 15,15,16 ; lfsu 7,0(15)")
GEN_test(LFDX,   "lfdx 7,15,16")
GEN_test(LFSX,   "lfsx 7,15,16")
GEN_test(LFDUX,  "lfdux 7,15,16")
GEN_test(LFSUX,  "lfsux 7,15,16")
GEN_test(STFD,   "add 15,15,16 ; stfd  7,0(15)")
GEN_test(STFS,   "add 15,15,16 ; stfs  7,0(15)")
GEN_test(STFDU,  "add 15,15,16 ; stfdu 7,0(15)")
GEN_test(STFSU,  "add 15,15,16 ; stfsu 7,0(15)")
GEN_test(STFDX,  "stfdx 7,15,16")
GEN_test(STFSX,  "stfsx 7,15,16")
GEN_test(STFDUX, "stfdux 7,15,16")
GEN_test(STFSUX, "stfsux 7,15,16")
GEN_test(STFIWX, "stfiwx 7,15,16")
GEN_test(LFIWAX, "lfiwax 7,15,16")
GEN_test(LFIWZX, "lfiwzx 7,15,16")

// Load F32x4
GEN_test(QVLFSX,    "qvlfsx     7,15,16")
GEN_test(QVLFSXA,   "qvlfsxa    7,15,16")
GEN_test(QVLFSUX,   "qvlfsux    7,15,16")
GEN_test(QVLFSUXA,  "qvlfsuxa   7,15,16")

// Load F64x4
GEN_test(QVLFDX,    "qvlfdx     7,15,16")
GEN_test(QVLFDXA,   "qvlfdxa    7,15,16")
GEN_test(QVLFDUX,   "qvlfdux    7,15,16")
GEN_test(QVLFDUXA,  "qvlfduxa   7,15,16")

// Load F32x2
GEN_test(QVLFCSX,   "qvlfcsx    7,15,16")
GEN_test(QVLFCSXA,  "qvlfcsxa   7,15,16")
GEN_test(QVLFCSUX,  "qvlfcsux   7,15,16")
GEN_test(QVLFCSUXA, "qvlfcsuxa  7,15,16")

// Load F64x2
GEN_test(QVLFCDX,   "qvlfcdx    7,15,16")
GEN_test(QVLFCDXA,  "qvlfcdxa   7,15,16")
GEN_test(QVLFCDUX,  "qvlfcdux   7,15,16")
GEN_test(QVLFCDUXA, "qvlfcduxa  7,15,16")

// Load I32Sx4
GEN_test(QVLFIWAX,  "qvlfiwax   7,15,16")
GEN_test(QVLFIWAXA, "qvlfiwaxa  7,15,16")

// Load I32Ux4
GEN_test(QVLFIWZX,  "qvlfiwzx   7,15,16")
GEN_test(QVLFIWZXA, "qvlfiwzxa  7,15,16")

// Generate permute control vectors (no memory access)
// Note that these depend only on the lowest 5 ish bits
// of the EA, that is, of (r15+r16).  Hence using them
// as-is is distinctly un-random; therefore use what they
// point at, which is the randomised memory operand.  Viz,
// replace them with *(r15+r16) and zero respectively.
GEN_test(QVLPCLDX,  "ldx 15,15,16 ; li 16,0 ; qvlpcldx 7,15,16")
GEN_test(QVLPCLSX,  "ldx 15,15,16 ; li 16,0 ; qvlpclsx 7,15,16")
GEN_test(QVLPCRDX,  "ldx 15,15,16 ; li 16,0 ; qvlpcrdx 7,15,16")
GEN_test(QVLPCRSX,  "ldx 15,15,16 ; li 16,0 ; qvlpcrsx 7,15,16")

// Store F32x4.
GEN_test(QVSTFSX,   "qvstfsx    7,15,16")
GEN_test(QVSTFSXA,  "qvstfsxa   7,15,16")
GEN_test(QVSTFSUX,  "qvstfsux   7,15,16")
GEN_test(QVSTFSUXA, "qvstfsuxa  7,15,16")

// Store-Indicate F32x4.
GEN_test(QVSTFSXI,   "qvstfsxi   7,15,16")
GEN_test(QVSTFSXIA,  "qvstfsxia  7,15,16")
GEN_test(QVSTFSUXI,  "qvstfsuxi  7,15,16")
GEN_test(QVSTFSUXIA, "qvstfsuxia 7,15,16")

// Store F64x4
GEN_test(QVSTFDX,   "qvstfdx    7,15,16")
GEN_test(QVSTFDXA,  "qvstfdxa   7,15,16")
GEN_test(QVSTFDUX,  "qvstfdux   7,15,16")
GEN_test(QVSTFDUXA, "qvstfduxa  7,15,16")

// Store-Indicate F64x4.
GEN_test(QVSTFDXI,   "qvstfdxi    7,15,16")
GEN_test(QVSTFDXIA,  "qvstfdxia   7,15,16")
GEN_test(QVSTFDUXI,  "qvstfduxi   7,15,16")
GEN_test(QVSTFDUXIA, "qvstfduxia  7,15,16")

// Store F32x2
GEN_test(QVSTFCSX,   "qvstfcsx    7,15,16")
GEN_test(QVSTFCSXA,  "qvstfcsxa   7,15,16")
GEN_test(QVSTFCSUX,  "qvstfcsux   7,15,16")
GEN_test(QVSTFCSUXA, "qvstfcsuxa  7,15,16")

// Store F64x2
GEN_test(QVSTFCDX,   "qvstfcdx    7,15,16")
GEN_test(QVSTFCDXA,  "qvstfcdxa   7,15,16")
GEN_test(QVSTFCDUX,  "qvstfcdux   7,15,16")
GEN_test(QVSTFCDUXA, "qvstfcduxa  7,15,16")

// Store-Indicate F32x2.
GEN_test(QVSTFCSXI,   "qvstfcsxi   7,15,16")
GEN_test(QVSTFCSXIA,  "qvstfcsxia  7,15,16")
GEN_test(QVSTFCSUXI,  "qvstfcsuxi  7,15,16")
GEN_test(QVSTFCSUXIA, "qvstfcsuxia 7,15,16")

// Store-Indicate F64x2.
GEN_test(QVSTFCDXI,   "qvstfcdxi   7,15,16")
GEN_test(QVSTFCDXIA,  "qvstfcdxia  7,15,16")
GEN_test(QVSTFCDUXI,  "qvstfcduxi  7,15,16")
GEN_test(QVSTFCDUXIA, "qvstfcduxia 7,15,16")

// Store I32x4 (copied directly from low halves)
GEN_test(QVSTFIWX,   "qvstfiwx   7,15,16")
GEN_test(QVSTFIWXA,  "qvstfiwxa  7,15,16")

// Move, Move-negate, Move-abs, Move-negAbs
GEN_test(QVFMR,    "qvfmr   9,6")
GEN_test(QVFNEG,   "qvfneg  9,6")
GEN_test(QVFABS,   "qvfabs  9,6")
GEN_test(QVFNABS,  "qvfnabs 9,6")

// Move, but copy sign from a different reg
GEN_test(QVFCPSGN,  "qvfcpsgn  9,6,8")

// {Add,Sub,Mul}64Fx4
GEN_test(QVFADD,  "qvfadd 7,8,6")
GEN_test(QVFSUB,  "qvfsub 7,8,6")
GEN_test(QVFMUL,  "qvfmul 7,8,6")

// {Add,Sub,Mul}64Fx4 but rounded to F32 range
GEN_test(QVFADDS,  "qvfadds 7,8,6")
GEN_test(QVFSUBS,  "qvfsubs 7,8,6")
GEN_test(QVFMULS,  "qvfmuls 7,8,6")

// Reciprocal estimate
GEN_test(QVFRE,   "qvfre 9,6")
GEN_test(QVFRES,  "qvfres 9,6")

// Reciprocal square root estimate
GEN_test(QVFRSQRTE,   "qvfrsqrte 9,6")
GEN_test(QVFRSQRTES,  "qvfrsqrtes 9,6")

// Multiply-add
GEN_test(QVFMADD,   "qvfmadd 7,8,6,9")
GEN_test(QVFMADDS,  "qvfmadds 7,8,6,9")

// Multiply-sub
GEN_test(QVFMSUB,   "qvfmsub 7,8,6,9")
GEN_test(QVFMSUBS,  "qvfmsubs 7,8,6,9")

// negated Multiply-add
GEN_test(QVFNMADD,   "qvfnmadd 7,8,6,9")
GEN_test(QVFNMADDS,  "qvfnmadds 7,8,6,9")

// negated Multiply-sub
GEN_test(QVFNMSUB,   "qvfnmsub 7,8,6,9")
GEN_test(QVFNMSUBS,  "qvfnmsubs 7,8,6,9")

// cross Multiply-add
GEN_test(QVFXMADD,   "qvfxmadd 7,8,6,9")
GEN_test(QVFXMADDS,  "qvfxmadds 7,8,6,9")

// double cross complex Multiply-add
GEN_test(QVFXXNPMADD,   "qvfxxnpmadd 7,8,6,9")
GEN_test(QVFXXNPMADDS,  "qvfxxnpmadds 7,8,6,9")

// double cross conjugate Multiply-add
GEN_test(QVFXXCPNMADD,   "qvfxxcpnmadd 7,8,6,9")
GEN_test(QVFXXCPNMADDS,  "qvfxxcpnmadds 7,8,6,9")

// double cross Multiply-add
GEN_test(QVFXXMADD,   "qvfxxmadd 7,8,6,9")
GEN_test(QVFXXMADDS,  "qvfxxmadds 7,8,6,9")

// cross Multiply
GEN_test(QVFXMUL,   "qvfxmul 8,6,9")
GEN_test(QVFXMULS,  "qvfxmuls 8,6,9")

// Round to single precision
GEN_test(QVFRSP,   "qvfrsp 6,9")

// Convert to I64/U64, rounding per RN
GEN_test(QVFCTID,   "qvfctid  7,9")
GEN_test(QVFCTIDU,  "qvfctidu 7,9")

// Convert to I64/U64, rounding towards zero
GEN_test(QVFCTIDZ,   "qvfctidz  7,9")
GEN_test(QVFCTIDUZ,  "qvfctiduz 7,9")

// Convert to I32/U32, rounding per RN
GEN_test(QVFCTIW,   "qvfctiw  7,9")
GEN_test(QVFCTIWU,  "qvfctiwu 7,9")

// Convert to I32/U32, rounding towards zero
GEN_test(QVFCTIWZ,   "qvfctiwz  7,9")
GEN_test(QVFCTIWUZ,  "qvfctiwuz 7,9")

// Convert from I64/U64
GEN_test(QVFCFID,   "qvfcfid  8,6")
GEN_test(QVFCFIDU,  "qvfcfidu  8,6")

// Convert from I64/U64, rounding to single range
GEN_test(QVFCFIDS,   "qvfcfids  8,6")
GEN_test(QVFCFIDUS,  "qvfcfidus  8,6")

// Round to integer: nearest, +inf, zero, -inf
GEN_test(QVFRIN,   "qvfrin  8,6")
GEN_test(QVFRIP,   "qvfrip  8,6")
GEN_test(QVFRIZ,   "qvfriz  8,6")
GEN_test(QVFRIM,   "qvfrim  8,6")

// Test for NaN
GEN_test(QVFTSTNAN,   "qvftstnan  9,8,6")

// Compare GT, LT, EQ
GEN_test(QVFCMPGT,   "qvfcmpgt  9,8,6")
GEN_test(QVFCMPLT,   "qvfcmplt  9,8,6")
GEN_test(QVFCMPEQ,   "qvfcmpeq  9,8,6")

// Select
GEN_test(QVFSEL,  "qvfsel 7,9,8,6")

// Align immediate
GEN_test(QVALIGNI_0,  "qvaligni 7,9,8, 0")
GEN_test(QVALIGNI_1,  "qvaligni 7,9,8, 1")
GEN_test(QVALIGNI_2,  "qvaligni 7,9,8, 2")
GEN_test(QVALIGNI_3,  "qvaligni 7,9,8, 3")

// Permute
GEN_test(QVFPERM,  "qvfperm 6,9,8,7")

// Splat immediate
GEN_test(QVESPLATI_0,  "qvesplati 8,7, 0")
GEN_test(QVESPLATI_1,  "qvesplati 8,7, 1")
GEN_test(QVESPLATI_2,  "qvesplati 8,7, 2")
GEN_test(QVESPLATI_3,  "qvesplati 8,7, 3")

// Generate permute control immediate
GEN_test(QVGPCI_0x000,  "qvgpci 9, 0x000")
GEN_test(QVGPCI_0xFFF,  "qvgpci 9, 0xFFF")
GEN_test(QVGPCI_0x555,  "qvgpci 9, 0x555")
GEN_test(QVGPCI_0xAAA,  "qvgpci 9, 0xAAA")
GEN_test(QVGPCI_0x314,  "qvgpci 9, 0x314")
GEN_test(QVGPCI_0x159,  "qvgpci 9, 0x159")
GEN_test(QVGPCI_0x265,  "qvgpci 9, 0x265")
GEN_test(QVGPCI_0x354,  "qvgpci 9, 0x354")

// Logical
GEN_test(QVFLOGICAL_0x0,  "qvflogical 7,9,8, 0x0")
GEN_test(QVFLOGICAL_0x1,  "qvflogical 7,9,8, 0x1")
GEN_test(QVFLOGICAL_0x2,  "qvflogical 7,9,8, 0x2")
GEN_test(QVFLOGICAL_0x3,  "qvflogical 7,9,8, 0x3")
GEN_test(QVFLOGICAL_0x4,  "qvflogical 7,9,8, 0x4")
GEN_test(QVFLOGICAL_0x5,  "qvflogical 7,9,8, 0x5")
GEN_test(QVFLOGICAL_0x6,  "qvflogical 7,9,8, 0x6")
GEN_test(QVFLOGICAL_0x7,  "qvflogical 7,9,8, 0x7")
GEN_test(QVFLOGICAL_0x8,  "qvflogical 7,9,8, 0x8")
GEN_test(QVFLOGICAL_0x9,  "qvflogical 7,9,8, 0x9")
GEN_test(QVFLOGICAL_0xA,  "qvflogical 7,9,8, 0xA")
GEN_test(QVFLOGICAL_0xB,  "qvflogical 7,9,8, 0xB")
GEN_test(QVFLOGICAL_0xC,  "qvflogical 7,9,8, 0xC")
GEN_test(QVFLOGICAL_0xD,  "qvflogical 7,9,8, 0xD")
GEN_test(QVFLOGICAL_0xE,  "qvflogical 7,9,8, 0xE")
GEN_test(QVFLOGICAL_0xF,  "qvflogical 7,9,8, 0xF")


/* Allowed operands in test instructions:
   QR6, QR7, QR8, QR9
   R15 and R16 which, when added, make a valid memory address
*/

#define N_DEFAULT_ITERS 20

// Do the specified test some number of times
#define DO_N(_iters, _testfn, _options) \
   do { int i; \
        for (i = 0; i < (_iters); i++) { \
           test_##_testfn(_options, i+1, (_iters)); \
           printf("\n"); \
        } \
   } while (0)

// Do the specified test the default number of times
#define DO_D(_testfn, _options) DO_N(N_DEFAULT_ITERS, _testfn, _options)


int main ( void )
{
   printf("test_qpx: begin\n");
   assert(sizeof(QReg) == 32);

   DO_D( LFD,            OPT_NONE );
   DO_D( LFS,            OPT_NONE );
   DO_D( LFDU,           OPT_NONE );
   DO_D( LFSU,           OPT_NONE );
   DO_D( LFDX,           OPT_NONE );
   DO_D( LFSX,           OPT_NONE );
   DO_D( LFDUX,          OPT_NONE );
   DO_D( LFSUX,          OPT_NONE );
   DO_D( STFD,           OPT_NONE );
   DO_D( STFS,           OPT_NONE );
   DO_D( STFDU,          OPT_NONE );
   DO_D( STFSU,          OPT_NONE );
   DO_D( STFDX,          OPT_NONE );
   DO_D( STFSX,          OPT_NONE );
   DO_D( STFDUX,         OPT_NONE );
   DO_D( STFSUX,         OPT_NONE );
   DO_D( STFIWX,         OPT_NONE );
   DO_D( LFIWAX,         OPT_NONE );
   DO_D( LFIWZX,         OPT_NONE );

   DO_D( QVLFSX,         OPT_NONE );
   DO_D( QVLFSXA,        OPT_NONE );
   DO_D( QVLFSUX,        OPT_NONE );
   DO_D( QVLFSUXA,       OPT_NONE );
   DO_D( QVLFDX,         OPT_NONE );
   DO_D( QVLFDXA,        OPT_NONE );
   DO_D( QVLFDUX,        OPT_NONE );
   DO_D( QVLFDUXA,       OPT_NONE );
   DO_D( QVLFCSX,        OPT_NONE );
   DO_D( QVLFCSXA,       OPT_NONE );
   DO_D( QVLFCSUX,       OPT_NONE );
   DO_D( QVLFCSUXA,      OPT_NONE );
   DO_D( QVLFCDX,        OPT_NONE );
   DO_D( QVLFCDXA,       OPT_NONE );
   DO_D( QVLFCDUX,       OPT_NONE );
   DO_D( QVLFCDUXA,      OPT_NONE );
   DO_D( QVLFIWAX,       OPT_NONE );
   DO_D( QVLFIWAXA,      OPT_NONE );
   DO_D( QVLFIWZX,       OPT_NONE );
   DO_D( QVLFIWZXA,      OPT_NONE );
   DO_N( 10, QVLPCLDX,   OPT_NONE );
   DO_N( 10, QVLPCLSX,   OPT_NONE );
   DO_N( 10, QVLPCRDX,   OPT_NONE );
   DO_N( 10, QVLPCRSX,   OPT_NONE );
   DO_D( QVSTFSX,        OPT_NONE );
   DO_D( QVSTFSXA,       OPT_NONE );
   DO_D( QVSTFSUX,       OPT_NONE );
   DO_D( QVSTFSUXA,      OPT_NONE );
   DO_D( QVSTFSXI,       OPT_NONE );
   DO_D( QVSTFSXIA,      OPT_NONE );
   DO_D( QVSTFSUXI,      OPT_NONE );
   DO_D( QVSTFSUXIA,     OPT_NONE );
   DO_D( QVSTFDX,        OPT_NONE );
   DO_D( QVSTFDXA,       OPT_NONE );
   DO_D( QVSTFDUX,       OPT_NONE );
   DO_D( QVSTFDUXA,      OPT_NONE );
   DO_D( QVSTFDXI,       OPT_NONE );
   DO_D( QVSTFDXIA,      OPT_NONE );
   DO_D( QVSTFDUXI,      OPT_NONE );
   DO_D( QVSTFDUXIA,     OPT_NONE );
   DO_D( QVSTFCSX,       OPT_NONE );
   DO_D( QVSTFCSXA,      OPT_NONE );
   DO_D( QVSTFCSUX,      OPT_NONE );
   DO_D( QVSTFCSUXA,     OPT_NONE );
   DO_D( QVSTFCDX,       OPT_NONE );
   DO_D( QVSTFCDXA,      OPT_NONE );
   DO_D( QVSTFCDUX,      OPT_NONE );
   DO_D( QVSTFCDUXA,     OPT_NONE );
   DO_D( QVSTFCSXI,      OPT_NONE );
   DO_D( QVSTFCSXIA,     OPT_NONE );
   DO_D( QVSTFCSUXI,     OPT_NONE );
   DO_D( QVSTFCSUXIA,    OPT_NONE );
   DO_D( QVSTFCDXI,      OPT_NONE );
   DO_D( QVSTFCDXIA,     OPT_NONE );
   DO_D( QVSTFCDUXI,     OPT_NONE );
   DO_D( QVSTFCDUXIA,    OPT_NONE );
   DO_D( QVSTFIWX,       OPT_NONE );
   DO_D( QVSTFIWXA,      OPT_NONE );
   DO_D( QVFMR,          OPT_NONE );
   DO_D( QVFNEG,         OPT_NONE );
   DO_D( QVFABS,         OPT_NONE );
   DO_D( QVFNABS,        OPT_NONE );
   DO_D( QVFCPSGN,       OPT_NONE );
   DO_D( QVFADD,         OPT_NONE );
   DO_D( QVFSUB,         OPT_NONE );
   DO_D( QVFMUL,         OPT_NONE );
   DO_D( QVFADDS,        OPT_NONE );
   DO_D( QVFSUBS,        OPT_NONE );
   DO_D( QVFMULS,        OPT_NONE );
   DO_D( QVFRE,          OPT_MASK_LO41 );
   DO_D( QVFRES,         OPT_MASK_LO41 );
   DO_D( QVFRSQRTE,      OPT_NONE );
   DO_D( QVFRSQRTES,     OPT_MASK_LO41 );
   DO_D( QVFMADD,        OPT_NONE );
   DO_D( QVFMADDS,       OPT_NONE );
   DO_D( QVFMSUB,        OPT_NONE );
   DO_D( QVFMSUBS,       OPT_NONE );
   DO_D( QVFNMADD,       OPT_NONE );
   DO_D( QVFNMADDS,      OPT_NONE );
   DO_D( QVFNMSUB,       OPT_NONE );
   DO_D( QVFNMSUBS,      OPT_NONE );
   DO_D( QVFXMADD,       OPT_NONE );
   DO_D( QVFXMADDS,      OPT_NONE );
   DO_D( QVFXXNPMADD,    OPT_NONE );
   DO_D( QVFXXNPMADDS,   OPT_NONE );
   DO_D( QVFXXCPNMADD,   OPT_NONE );
   DO_D( QVFXXCPNMADDS,  OPT_NONE );
   DO_D( QVFXXMADD,      OPT_NONE );
   DO_D( QVFXXMADDS,     OPT_NONE );
   DO_D( QVFXMUL,        OPT_NONE );
   DO_D( QVFXMULS,       OPT_NONE );
   DO_D( QVFRSP,         OPT_NONE );
   DO_D( QVFCTID,        OPT_NONE );
   DO_D( QVFCTIDU,       OPT_NONE );
   DO_D( QVFCTIDZ,       OPT_NONE );
   DO_D( QVFCTIDUZ,      OPT_NONE );
   DO_D( QVFCTIW,        OPT_NONE );
   DO_D( QVFCTIWU,       OPT_NONE );
   DO_D( QVFCTIWZ,       OPT_NONE );
   DO_D( QVFCTIWUZ,      OPT_NONE );
   DO_D( QVFCFID,        OPT_NONE );
   DO_D( QVFCFIDU,       OPT_NONE );
   DO_D( QVFCFIDS,       OPT_NONE );
   DO_D( QVFCFIDUS,      OPT_NONE );
   DO_D( QVFRIN,         OPT_NONE );
   DO_D( QVFRIP,         OPT_NONE );
   DO_D( QVFRIZ,         OPT_NONE );
   DO_D( QVFRIM,         OPT_NONE );
   DO_D( QVFTSTNAN,      OPT_NONE );
   DO_D( QVFCMPGT,       OPT_NONE );
   DO_D( QVFCMPLT,       OPT_NONE );
   DO_D( QVFCMPEQ,       OPT_NONE );
   DO_D( QVFSEL,         OPT_NONE );
   DO_D( QVALIGNI_0,     OPT_NONE );
   DO_D( QVALIGNI_1,     OPT_NONE );
   DO_D( QVALIGNI_2,     OPT_NONE );
   DO_D( QVALIGNI_3,     OPT_NONE );
   DO_D( QVFPERM,        OPT_NONE );
   DO_D( QVESPLATI_0,    OPT_NONE );
   DO_D( QVESPLATI_1,    OPT_NONE );
   DO_D( QVESPLATI_2,    OPT_NONE );
   DO_D( QVESPLATI_3,    OPT_NONE );
   DO_D( QVGPCI_0x000,   OPT_NONE );
   DO_D( QVGPCI_0xFFF,   OPT_NONE );
   DO_D( QVGPCI_0x555,   OPT_NONE );
   DO_D( QVGPCI_0xAAA,   OPT_NONE );
   DO_D( QVGPCI_0x314,   OPT_NONE );
   DO_D( QVGPCI_0x159,   OPT_NONE );
   DO_D( QVGPCI_0x265,   OPT_NONE );
   DO_D( QVGPCI_0x354,   OPT_NONE );
   DO_D( QVFLOGICAL_0x0, OPT_NONE );
   DO_D( QVFLOGICAL_0x1, OPT_NONE );
   DO_D( QVFLOGICAL_0x2, OPT_NONE );
   DO_D( QVFLOGICAL_0x3, OPT_NONE );
   DO_D( QVFLOGICAL_0x4, OPT_NONE );
   DO_D( QVFLOGICAL_0x5, OPT_NONE );
   DO_D( QVFLOGICAL_0x6, OPT_NONE );
   DO_D( QVFLOGICAL_0x7, OPT_NONE );
   DO_D( QVFLOGICAL_0x8, OPT_NONE );
   DO_D( QVFLOGICAL_0x9, OPT_NONE );
   DO_D( QVFLOGICAL_0xA, OPT_NONE );
   DO_D( QVFLOGICAL_0xB, OPT_NONE );
   DO_D( QVFLOGICAL_0xC, OPT_NONE );
   DO_D( QVFLOGICAL_0xD, OPT_NONE );
   DO_D( QVFLOGICAL_0xE, OPT_NONE );
   DO_D( QVFLOGICAL_0xF, OPT_NONE );
   printf("test_qpx: end\n");
   return 0;
}
