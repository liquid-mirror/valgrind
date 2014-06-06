
#include <unistd.h>
#include "/g/g92/seward3/BGQ/VgTRUNK/branch38bgq/include/valgrind.h"

typedef unsigned long long int UWord;

static void writestr ( char* str )
{
  int i, j;
  char buf[64];
  for (i = 0; i < sizeof(buf); i++) buf[i] = ' ';
  for (i = 0; i < sizeof(buf)-1 && str[i]; i++) buf[i] = str[i];
  buf[sizeof(buf)-1] = '\n';
  write(2, buf, sizeof(buf));
}

char* I_WRAP_SONAME_FNNAME_ZU(NONE,getenv)(const char *name)
{
  OrigFn fn;
  UWord result;
  VALGRIND_GET_ORIG_FN(fn);
  CALL_FN_W_W(result, fn, name);

  writestr(name);
  if (result == 0) {
    writestr("zeeero");
  } else {
    writestr( (char*)result );
  }

  return(char*)result;
}
