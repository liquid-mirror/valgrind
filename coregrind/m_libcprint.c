
/*--------------------------------------------------------------------*/
/*--- Libc printing.                                 m_libcprint.c ---*/
/*--------------------------------------------------------------------*/
 
/*
   This file is part of Valgrind, a dynamic binary instrumentation
   framework.

   Copyright (C) 2000-2009 Julian Seward 
      jseward@acm.org

   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   This program is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307, USA.

   The GNU General Public License is contained in the file COPYING.
*/

#include "pub_core_basics.h"
#include "pub_core_vki.h"
#include "pub_core_debuglog.h"
#include "pub_core_libcbase.h"
#include "pub_core_libcassert.h"
#include "pub_core_libcfile.h"   // VG_(write)(), VG_(write_socket)()
#include "pub_core_libcprint.h"
#include "pub_core_libcproc.h"   // VG_(getpid)(), VG_(read_millisecond_timer()
#include "pub_core_options.h"
#include "valgrind.h"            // For RUNNING_ON_VALGRIND



/* ---------------------------------------------------------------------
   Writing to file or a socket
   ------------------------------------------------------------------ */

/* Tell the logging mechanism whether we are logging to a file
   descriptor or a socket descriptor. */
Bool VG_(logging_to_socket) = False;

/* Do the low-level send of a message to the logging sink. */
static void send_bytes_to_logging_sink ( Char* msg, Int nbytes )
{
   if (!VG_(logging_to_socket)) {
      /* VG_(clo_log_fd) could have been set to -1 in the various
         sys-wrappers for sys_fork, if --child-silent-after-fork=yes
         is in effect.  That is a signal that we should not produce
         any more output. */
      if (VG_(clo_log_fd) >= 0)
         VG_(write)( VG_(clo_log_fd), msg, nbytes );
   } else {
      Int rc = VG_(write_socket)( VG_(clo_log_fd), msg, nbytes );
      if (rc == -1) {
         // For example, the listener process died.  Switch back to stderr.
         VG_(logging_to_socket) = False;
         VG_(clo_log_fd) = 2;
         VG_(write)( VG_(clo_log_fd), msg, nbytes );
      }
   }
}

/* ---------------------------------------------------------------------
   printf() and friends
   ------------------------------------------------------------------ */

/* --------- printf --------- */

typedef 
   struct {
      HChar buf[512];
      Int   buf_used;
   } 
   printf_buf_t;

// Adds a single char to the buffer.  When the buffer gets sufficiently
// full, we write its contents to the logging sink.
static void add_to__printf_buf ( HChar c, void *p )
{
   printf_buf_t *b = (printf_buf_t *)p;
   
   if (b->buf_used > sizeof(b->buf) - 2 ) {
      send_bytes_to_logging_sink( b->buf, b->buf_used );
      b->buf_used = 0;
   }
   b->buf[b->buf_used++] = c;
   b->buf[b->buf_used]   = 0;
   tl_assert(b->buf_used < sizeof(b->buf));
}

static UInt vprintf_to_buf ( printf_buf_t *prbuf,
                             const HChar *format, va_list vargs )
{
   UInt ret = 0;

   if (VG_(clo_log_fd) >= 0) {
      ret = VG_(debugLog_vprintf) 
               ( add_to__printf_buf, prbuf, format, vargs );
   }
   return ret;
}

UInt VG_(vprintf) ( const HChar *format, va_list vargs )
{
   UInt ret = 0;
   printf_buf_t myprintf_buf = {"",0};

   ret = vprintf_to_buf(&myprintf_buf, format, vargs);
   // Write out any chars left in the buffer.
   if (myprintf_buf.buf_used > 0) {
      send_bytes_to_logging_sink( myprintf_buf.buf,
                                  myprintf_buf.buf_used );
   }
   return ret;
}

UInt VG_(printf) ( const HChar *format, ... )
{
   UInt ret;
   va_list vargs;

   va_start(vargs, format);
   ret = VG_(vprintf)(format, vargs);
   va_end(vargs);

   return ret;
}

//static UInt printf_to_buf ( printf_buf_t* prbuf, const HChar *format, ... )
//{
//   UInt ret;
//   va_list vargs;
//
//   va_start(vargs, format);
//   ret = vprintf_to_buf(prbuf, format, vargs);
//   va_end(vargs);
//
//   return ret;
//}


/* --------- sprintf --------- */

/* If we had an explicit buf structure here, it would contain only one
   field, indicating where the next char is to go.  So use p directly
   for that, rather than having it be a pointer to a structure. */

static void add_to__sprintf_buf ( HChar c, void *p )
{
   HChar** b = p;
   *(*b)++ = c;
}

UInt VG_(vsprintf) ( Char* buf, const HChar *format, va_list vargs )
{
   Int ret;
   HChar* sprintf_ptr = buf;

   ret = VG_(debugLog_vprintf) 
            ( add_to__sprintf_buf, &sprintf_ptr, format, vargs );
   add_to__sprintf_buf('\0', &sprintf_ptr);

   vg_assert(VG_(strlen)(buf) == ret);

   return ret;
}

UInt VG_(sprintf) ( Char* buf, const HChar *format, ... )
{
   UInt ret;
   va_list vargs;

   va_start(vargs,format);
   ret = VG_(vsprintf)(buf, format, vargs);
   va_end(vargs);

   return ret;
}


/* --------- snprintf --------- */

typedef 
   struct {
      HChar* buf;
      Int    buf_size;
      Int    buf_used;
   } 
   snprintf_buf_t;

static void add_to__snprintf_buf ( HChar c, void* p )
{
   snprintf_buf_t* b = p;
   if (b->buf_size > 0 && b->buf_used < b->buf_size) {
      b->buf[b->buf_used++] = c;
      if (b->buf_used < b->buf_size)
         b->buf[b->buf_used] = 0;
      else
         b->buf[b->buf_size-1] = 0; /* pre: b->buf_size > 0 */
   } 
}

UInt VG_(vsnprintf) ( Char* buf, Int size, const HChar *format, va_list vargs )
{
   Int ret;
   snprintf_buf_t b;
   b.buf      = buf;
   b.buf_size = size < 0 ? 0 : size;
   b.buf_used = 0;

   ret = VG_(debugLog_vprintf) 
            ( add_to__snprintf_buf, &b, format, vargs );

   return b.buf_used;
}

UInt VG_(snprintf) ( Char* buf, Int size, const HChar *format, ... )
{
   UInt ret;
   va_list vargs;

   va_start(vargs,format);
   ret = VG_(vsnprintf)(buf, size, format, vargs);
   va_end(vargs);

   return ret;
}


/* ---------------------------------------------------------------------
   percentify()
   ------------------------------------------------------------------ */

// Percentify n/m with d decimal places.  Includes the '%' symbol at the end.
// Right justifies in 'buf'.
void VG_(percentify)(ULong n, ULong m, UInt d, Int n_buf, char buf[]) 
{
   Int i, len, space;
   ULong p1;
   Char fmt[32];

   if (m == 0) {
      // Have to generate the format string in order to be flexible about
      // the width of the field.
      VG_(sprintf)(fmt, "%%-%ds", n_buf);
      // fmt is now "%<n_buf>s" where <d> is 1,2,3...
      VG_(sprintf)(buf, fmt, "--%");
      return;
   }
   
   p1 = (100*n) / m;
    
   if (d == 0) {
      VG_(sprintf)(buf, "%lld%%", p1);
   } else {
      ULong p2;
      UInt  ex;
      switch (d) {
      case 1: ex = 10;    break;
      case 2: ex = 100;   break;
      case 3: ex = 1000;  break;
      default: VG_(tool_panic)("Currently can only handle 3 decimal places");
      }
      p2 = ((100*n*ex) / m) % ex;
      // Have to generate the format string in order to be flexible about
      // the width of the post-decimal-point part.
      VG_(sprintf)(fmt, "%%lld.%%0%dlld%%%%", d);
      // fmt is now "%lld.%0<d>lld%%" where <d> is 1,2,3...
      VG_(sprintf)(buf, fmt, p1, p2);
   }

   len = VG_(strlen)(buf);
   space = n_buf - len;
   if (space < 0) space = 0;     /* Allow for v. small field_width */
   i = len;

   /* Right justify in field */
   for (     ; i >= 0;    i--)  buf[i + space] = buf[i];
   for (i = 0; i < space; i++)  buf[i] = ' ';
}


/* ---------------------------------------------------------------------
   elapsed_wallclock_time()
   ------------------------------------------------------------------ */

/* Get the elapsed wallclock time since startup into buf, which must
   16 chars long.  This is unchecked.  It also relies on the
   millisecond timer having been set to zero by an initial read in
   m_main during startup. */

void VG_(elapsed_wallclock_time) ( /*OUT*/HChar* buf )
{
   UInt t, ms, s, mins, hours, days;

   t  = VG_(read_millisecond_timer)(); /* milliseconds */

   ms = t % 1000;
   t /= 1000; /* now in seconds */

   s = t % 60;
   t /= 60; /* now in minutes */

   mins = t % 60;
   t /= 60; /* now in hours */

   hours = t % 24;
   t /= 24; /* now in days */

   days = t;

   VG_(sprintf)(buf, "%02u:%02u:%02u:%02u.%03u", days, hours, mins, s, ms);
}


/* ---------------------------------------------------------------------
   message()
   ------------------------------------------------------------------ */

/* A buffer for accumulating VG_(message) style output.  This is
   pretty much the same as VG_(printf)'s scheme, with two differences:

   * The message buffer persists between calls, so that multiple
     calls to VG_(message) can build up output.

   * Whenever the first character on a line is emitted, the
     ==PID== style preamble is stuffed in before it.
*/
typedef 
   struct {
      HChar buf[512+128];
      Int   buf_used;
      Bool  atLeft; /* notionally, is the next char position at the
                       leftmost column? */
      VgMsgKind kind;
      Int my_pid;
   } 
   vmessage_buf_t;

static vmessage_buf_t vmessage_buf = {"", 0, True, Vg_UserMsg, -1};


// Adds a single char to the buffer.  We aim to have at least 128
// bytes free in the buffer, so that it's always possible to emit
// the preamble into the buffer if c happens to be the character
// following a \n.  When the buffer gets too full, we write its
// contents to the logging sink.
static void add_to__vmessage_buf ( HChar c, void *p )
{
   HChar tmp[64];
   vmessage_buf_t* b = (vmessage_buf_t*)p;

   vg_assert(b->buf_used >= 0 && b->buf_used < sizeof(b->buf)-128);

   if (UNLIKELY(b->atLeft)) {
      // insert preamble
      HChar ch;
      Int   i, depth;

      switch (b->kind) {
         case Vg_UserMsg:       ch = '='; break;
         case Vg_DebugMsg:      ch = '-'; break;
         case Vg_DebugExtraMsg: ch = '+'; break;
         case Vg_ClientMsg:     ch = '*'; break;
         default:               ch = '?'; break;
      }

      // Print one '>' in front of the messages for each level of
      // self-hosting being performed.
      depth = RUNNING_ON_VALGRIND;
      if (depth > 10)
         depth = 10; // ?!?!
      for (i = 0; i < depth; i++) {
         b->buf[b->buf_used++] = '>';
      }

      b->buf[b->buf_used++] = ch;
      b->buf[b->buf_used++] = ch;

      if (VG_(clo_time_stamp)) {
         VG_(memset)(tmp, 0, sizeof(tmp));
         VG_(elapsed_wallclock_time)(tmp);
         tmp[sizeof(tmp)-1] = 0;
         for (i = 0; tmp[i]; i++)
            b->buf[b->buf_used++] = tmp[i];
      }

      VG_(sprintf)(tmp, "%d", b->my_pid);
      tmp[sizeof(tmp)-1] = 0;
      for (i = 0; tmp[i]; i++)
         b->buf[b->buf_used++] = tmp[i];

      b->buf[b->buf_used++] = ch;
      b->buf[b->buf_used++] = ch;
      b->buf[b->buf_used++] = ' ';

      /* We can't possibly have stuffed 96 chars in merely as a result
         of making the preamble (can we?) */
      vg_assert(b->buf_used < sizeof(b->buf)-32);
   }

   b->buf[b->buf_used++] = c;
   b->buf[b->buf_used]   = 0;
   
   if (b->buf_used >= sizeof(b->buf) - 128) {
      send_bytes_to_logging_sink( b->buf, b->buf_used );
      b->buf_used = 0;
   }

   b->atLeft = c == '\n';
}


UInt VG_(vmessage) ( VgMsgKind kind, const HChar* format, va_list vargs )
{
   UInt ret;

   /* Note (carefully) that the buf persists from call to call, unlike
      with the other printf variants in earlier parts of this file. */
   vmessage_buf_t* b = &vmessage_buf; /* shorthand for convenience */

   /* We have to set this each call, so that the correct flavour
      of preamble is emitted at each \n. */
   b->kind = kind;

   /* Cache the results of getpid just once, so we don't have to call
      getpid once for each line of text output. */
   if (UNLIKELY(b->my_pid == -1)) {
      b->my_pid = VG_(getpid)();
      vg_assert(b->my_pid >= 0);
   }

   ret = VG_(debugLog_vprintf) ( add_to__vmessage_buf,
                                 b, format, vargs );

   /* If the message finished exactly with a \n, then flush it at this
      point.  If not, assume more bits of the same line will turn up
      in later messages, so don't bother to flush it right now. */

   if (b->atLeft && b->buf_used > 0) {
      send_bytes_to_logging_sink( b->buf, b->buf_used );
      b->buf_used = 0;
   }

   return ret;
}

/* Send a simple single-part XML message. */
UInt VG_(message_no_f_c) ( VgMsgKind kind, const HChar* format, ... )
{
   UInt count;
   va_list vargs;
   va_start(vargs,format);
   count = VG_(vmessage) ( kind, format, vargs );
   va_end(vargs);
   return count;
}

/* Send a simple single-part message. */
UInt VG_(message) ( VgMsgKind kind, const HChar* format, ... )
{
   UInt count;
   va_list vargs;
   va_start(vargs,format);
   count = VG_(vmessage) ( kind, format, vargs );
   va_end(vargs);
   return count;
}

/* Flush any output that has accumulated in vmessage_buf as a 
   result of previous calls to VG_(message) et al. */
void VG_(message_flush) ( void )
{
   vmessage_buf_t* b = &vmessage_buf;
   send_bytes_to_logging_sink( b->buf, b->buf_used );
   b->buf_used = 0;
}


/*--------------------------------------------------------------------*/
/*--- end                                                          ---*/
/*--------------------------------------------------------------------*/

