
   // Comment "both" means tp[0] and tp[-1] are both bad.
   // Otherwise only tp[-1] is bad.

   #define TTT \
      if (__builtin_setjmp(TTT_jmpbuf) == 0) \
      { fprintf(stderr,  "about to do %d [0]\n", __LINE__); tn = tp[ 0]; } \
      if (__builtin_setjmp(TTT_jmpbuf) == 0) \
      { fprintf(stderr, "about to do %d [-1]\n", __LINE__); tn = tp[-1]; }

   #define b(    a,  c)   tp = (int*)a;                    TTT
   #define ui(op, a,  c)  tp = (int*)op(int)a;             TTT
   #define g(op, a,b,c)   tp = (int*)((int)a op (int)b);   TTT
   #define UNU            __attribute__((unused))

   struct sigaction sigsegv;
   // Scratch values
   int  a, tn;
   int* tp;
   
   // Known pointers
   int* p = malloc(sizeof(int)*10);  UNU int* p2 = malloc(sizeof(int)*10);
   UNU int* pp = p;
   // Unknown pointers
//   int up[10], UNU up2[10];

   // Known nonptrs;  make them zero and known
   int n = a ^ a, UNU n2 = n+1, UNU n7F = 0x7fffffff, UNU nFF = ~n;
   
   // Unknown nonptrs;  make them zero but unknown
   int un = 0x01100000, UNU un2 = un;

   // Known nonptr, from pointerness range check
   UNU int nn = 0;

   // Intall SEGV handler 
   memset(&sigsegv, 0, sizeof(sigsegv));
   sigsegv.sa_handler = SEGV_handler;
   sigsegv.sa_flags   = SA_NODEFER; /* so we can handle signal many times */
   assert( 0 == sigemptyset( &sigsegv.sa_mask ) );
   assert( 0 == sigaction(SIGSEGV, &sigsegv, NULL) );
