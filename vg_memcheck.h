

#include "valgrind.h"

// SSS: client requests... dodgy 
#define VG_USERREQ__DO_LEAK_CHECK   6000    // SSS: do better

/* Do a memory leak check mid-execution.
   Currently implemented but untested.
*/
#define VALGRIND_DO_LEAK_CHECK                                     \
   {unsigned int _qzz_res;                                         \
    VALGRIND_MAGIC_SEQUENCE(_qzz_res, 0,                           \
                            VG_USERREQ__DO_LEAK_CHECK,             \
                            0, 0, 0, 0);                           \
   }



