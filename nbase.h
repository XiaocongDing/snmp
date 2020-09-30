#pragma once
#if HAVE_CONFIG_H
#include "nbase_config.h"
#else

#if HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <stdlib.h>
#include <ctype.h>
#include <time.h>

#if HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif

#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#if HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#if HAVE_STRING_H
#include <string.h>
#endif

#if HAVE_NETDB_H
#include <netdb.h>
#endif

#if HAVE_INTTYPES_H
#include <inttypes.h>
#endif

#include <stdio.h>

#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 64
#endif

#ifndef MAXPATHLEN
#define MAXPATHLEN 2048
#endif

#ifndef HAVE___ATTRIBUTE__
#define __attribute__(args)
#endif

#include <stdarg.h>

/* Keep assert() defined for security reasons */
#undef NDEBUG

/* Integer types */
#include <stdint.h>
typedef uint8_t u8;
typedef int8_t s8;
typedef uint16_t u16;
typedef int16_t s16;
typedef uint32_t u32;
typedef int32_t s32;
typedef uint64_t u64;
typedef int64_t s64;

/* Mathematical MIN/MAX/ABS (absolute value) macros */
#ifndef MAX
#define MAX(x,y) (((x)>(y))?(x):(y))
#endif
#ifndef MIN
#define MIN(x,y) (((x)<(y))?(x):(y))
#endif
#ifndef ABS
#define ABS(x) (((x) >= 0)?(x):-(x))
#endif

/* Timeval subtraction in microseconds */
#define TIMEVAL_SUBTRACT(a,b) (((a).tv_sec - (b).tv_sec) * 1000000 + (a).tv_usec - (b).tv_usec)
/* Timeval subtract in milliseconds */
#define TIMEVAL_MSEC_SUBTRACT(a,b) ((((a).tv_sec - (b).tv_sec) * 1000) + ((a).tv_usec - (b).tv_usec) / 1000)
/* Timeval subtract in seconds; truncate towards zero */
#define TIMEVAL_SEC_SUBTRACT(a,b) ((a).tv_sec - (b).tv_sec + (((a).tv_usec < (b).tv_usec) ? - 1 : 0))
/* Timeval subtract in fractional seconds; convert to float */
#define TIMEVAL_FSEC_SUBTRACT(a,b) ((a).tv_sec - (b).tv_sec + (((a).tv_usec - (b).tv_usec)/1000000.0))

/* assign one timeval to another timeval plus some msecs: a = b + msecs */
#define TIMEVAL_MSEC_ADD(a, b, msecs) { (a).tv_sec = (b).tv_sec + ((msecs) / 1000); (a).tv_usec = (b).tv_usec + ((msecs) % 1000) * 1000; (a).tv_sec += (a).tv_usec / 1000000; (a).tv_usec %= 1000000; }
#define TIMEVAL_ADD(a, b, usecs) { (a).tv_sec = (b).tv_sec + ((usecs) / 1000000); (a).tv_usec = (b).tv_usec + ((usecs) % 1000000); (a).tv_sec += (a).tv_usec / 1000000; (a).tv_usec %= 1000000; }

/* Find our if one timeval is before or after another, avoiding the integer
   overflow that can result when doing a TIMEVAL_SUBTRACT on two widely spaced
   timevals. */
#define TIMEVAL_BEFORE(a, b) (((a).tv_sec < (b).tv_sec) || ((a).tv_sec == (b).tv_sec && (a).tv_usec < (b).tv_usec))
#define TIMEVAL_AFTER(a, b) (((a).tv_sec > (b).tv_sec) || ((a).tv_sec == (b).tv_sec && (a).tv_usec > (b).tv_usec))

   /* Convert a timeval to floating point seconds */
#define TIMEVAL_SECS(a) ((double) (a).tv_sec + (double) (a).tv_usec / 1000000)


/* sprintf family */
#if !defined(HAVE_SNPRINTF) && defined(__cplusplus)
extern "C" int snprintf(char* str, size_t sz, const char* format, ...)
__attribute__((format(printf, 3, 4)));
#endif

#if !defined(HAVE_VSNPRINTF) && defined(__cplusplus)
extern "C" int vsnprintf(char* str, size_t sz, const char* format,
    va_list ap)
    __attribute__((format(printf, 3, 0)));
#endif

#if !defined(HAVE_ASPRINTF) && defined(__cplusplus)
extern "C" int asprintf(char** ret, const char* format, ...)
__attribute__((format(printf, 2, 3)));
#endif

#if !defined(HAVE_VASPRINTF) && defined(__cplusplus)
extern "C" int vasprintf(char** ret, const char* format, va_list ap)
__attribute__((format(printf, 2, 0)));
#endif

#if !defined(HAVE_ASNPRINTF) && defined(__cplusplus)
extern "C" int asnprintf(char** ret, size_t max_sz, const char* format, ...)
__attribute__((format(printf, 3, 4)));
#endif

#if !defined(HAVE_VASNPRINTF) && defined(__cplusplus)
extern "C" int vasnprintf(char** ret, size_t max_sz, const char* format,
    va_list ap)
    __attribute__((format(printf, 3, 0)));
#endif

#if defined(NEED_SNPRINTF_PROTO) && defined(__cplusplus)
extern "C" int snprintf(char*, size_t, const char*, ...);
#endif

#if defined(NEED_VSNPRINTF_PROTO) && defined(__cplusplus)
extern "C" int vsnprintf(char*, size_t, const char*, va_list);
#endif

#ifdef HAVE_GETOPT_H
#include <getopt.h>
#else
#ifndef HAVE_GETOPT_LONG_ONLY

#endif
#endif /* HAVE_GETOPT_H */

/* More Windows-specific stuff */
#ifdef WIN32

#define WIN32_LEAN_AND_MEAN /* Whatever this means! From winclude.h*/

/* Apparently Windows doesn't have S_ISDIR */
#ifndef S_ISDIR
#define S_ISDIR(m)      (((m) & _S_IFMT) == _S_IFDIR)
#endif

/* Windows doesn't have the access() defines */
#ifndef F_OK
#define F_OK 00
#endif
#ifndef W_OK
#define W_OK 02
#endif
#ifndef R_OK
#define R_OK 04
#endif

/* wtf was ms thinking? */
#define access _access
#define stat _stat
#define execve _execve
#define getpid _getpid
#define dup _dup
#define dup2 _dup2
#define strdup _strdup
#define write _write
#define open _open
#define stricmp _stricmp
#define putenv _putenv
#define tzset _tzset

#if !defined(__GNUC__)
#define snprintf _snprintf
#endif

#define strcasecmp _stricmp
#define strncasecmp _strnicmp
#define execv _execv

#endif /* WIN32 */

/* Apparently Windows doesn't like /dev/null */
#ifdef WIN32
#define DEVNULL "NUL"
#else
#define DEVNULL "/dev/null"
#endif

#if defined(_MSC_VER) && !defined(__cplusplus) && !defined(inline)
#define inline __inline
#endif

#if defined(__GNUC__)
#define NORETURN __attribute__((noreturn))
#elif defined(_MSC_VER)
#define NORETURN __declspec(noreturn)
#else
#define NORETURN
#endif


//static inline int checked_fd_isset(int fd, fd_set* fds) {
//#ifndef WIN32
//    if (fd >= FD_SETSIZE) {
//        fprintf(stderr, "Attempt to FD_ISSET fd %d, which is not less than "
//            "FD_SETSIZE (%d). Try using a lower parallelism.",
//            fd, FD_SETSIZE);
//        abort();
//    }
//#endif
//    return FD_ISSET(fd, fds);
//}
//
//static inline void checked_fd_clr(int fd, fd_set* fds) {
//#ifndef WIN32
//    if (fd >= FD_SETSIZE) {
//        fprintf(stderr, "Attempt to FD_CLR fd %d, which is not less than "
//            "FD_SETSIZE (%d). Try using a lower parallelism.",
//            fd, FD_SETSIZE);
//        abort();
//    }
//#endif
//    FD_CLR(fd, fds);
//}
//
//static inline void checked_fd_set(int fd, fd_set* fds) {
//#ifndef WIN32
//    if (fd >= FD_SETSIZE) {
//        fprintf(stderr, "Attempt to FD_SET fd %d, which is not less than "
//            "FD_SETSIZE (%d). Try using a lower parallelism.",
//            fd, FD_SETSIZE);
//        abort();
//    }
//#endif
//    FD_SET(fd, fds);
//}


#ifdef __cplusplus
extern "C" {
#endif

    /* Returns the UNIX/Windows errno-equivalent.  Note that the Windows
       call is socket/networking specific.  Also, WINDOWS TENDS TO RESET
       THE ERROR, so it will return success the next time.  So SAVE THE
       RESULTS and re-use them, don't keep calling socket_errno().  The
       windows error number returned is like WSAMSGSIZE, but nbase.h
       includes #defines to correlate many of the common UNIX errors
       with their closest Windows equivalents.  So you can use EMSGSIZE
       or EINTR. */
    int socket_errno();

    /* We can't just use strerror to get socket errors on Windows because it has
       its own set of error codes: WSACONNRESET not ECONNRESET for example. This
       function will do the right thing on Windows. Call it like
         socket_strerror(socket_errno())
    */
    char* socket_strerror(int errnum);

    /* The usleep() function is important as well */
#ifndef HAVE_USLEEP
#if defined( HAVE_NANOSLEEP) || defined(WIN32)
    void usleep(unsigned long usec);
#endif
#endif

    /* localtime is not thread safe. This will use a thread safe alternative on
     * supported platforms. */
    int n_localtime(const time_t* timer, struct tm* result);
    int n_gmtime(const time_t* timer, struct tm* result);
    int n_ctime(char* buffer, size_t bufsz, const time_t* timer);

    /***************** String functions -- See nbase_str.c ******************/
    /* I modified this conditional because !@# Redhat does not easily provide
       the prototype even though the function exists */
#if !defined(HAVE_STRCASESTR) || (defined(LINUX) && !defined(__USE_GNU) && !defined(_GNU_SOURCE))
       /* strcasestr is like strstr() except case insensitive */
    char* strcasestr(const char* haystack, const char* pneedle);
#endif

#ifndef HAVE_STRCASECMP
    int strcasecmp(const char* s1, const char* s2);
#endif

#ifndef HAVE_STRNCASECMP
    int strncasecmp(const char* s1, const char* s2, size_t n);
#endif

#ifndef HAVE_GETTIMEOFDAY
    int gettimeofday(struct timeval* tv, struct timeval* tz);
#endif

#ifndef HAVE_SLEEP
    unsigned int sleep(unsigned int seconds);
#endif

    /* Strncpy is like strcpy() except it ALWAYS zero-terminates, even if
       it must truncate */
    int Strncpy(char* dest, const char* src, size_t n);

    int Vsnprintf(char*, size_t, const char*, va_list)
        __attribute__((format(printf, 3, 0)));
    int Snprintf(char*, size_t, const char*, ...)
        __attribute__((format(printf, 3, 4)));

    char* mkstr(const char* start, const char* end);

    int alloc_vsprintf(char** strp, const char* fmt, va_list va)
        __attribute__((format(printf, 2, 0)));

    char* escape_windows_command_arg(const char* arg);

    /* parse_long is like strtol or atoi, but it allows digits only.
       No whitespace, sign, or radix prefix. */
    long parse_long(const char* s, char** tail);

    /* This function takes a byte count and stores a short ascii equivalent
       in the supplied buffer. Eg: 0.122MB, 10.322Kb or 128B. */
    char* format_bytecount(unsigned long long bytes, char* buf, size_t buflen);

    /* Convert non-printable characters to replchar in the string */
    void replacenonprintable(char* str, int strlength, char replchar);

    /* Returns one if the file pathname given exists, is not a directory and
     * is readable by the executing process.  Returns two if it is readable
     * and is a directory.  Otherwise returns 0. */
    int file_is_readable(const char* pathname);

    /* Portable, incompatible replacements for dirname and basename. */
    char* path_get_dirname(const char* path);
    char* path_get_basename(const char* path);

    /* A few simple wrappers for the most common memory allocation routines which will exit() if the
       allocation fails, so you don't always have to check -- see nbase_memalloc.c */
    void* safe_malloc(size_t size);
    void* safe_realloc(void* ptr, size_t size);
    /* Zero-initializing version of safe_malloc */
    void* safe_zalloc(size_t size);

    /* Some routines for obtaining simple (not secure on systems that
       lack /dev/random and friends' "random" numbers */
    int get_random_bytes(void* buf, int numbytes);
    int get_random_int();
    unsigned short get_random_ushort();
    unsigned int get_random_uint();
    u64 get_random_u64();
    u32 get_random_u32();
    u16 get_random_u16();
    u8 get_random_u8();
    u32 get_random_unique_u32();

    /* Create a new socket inheritable by subprocesses. On non-Windows systems it's
       just a normal socket. */
    int inheritable_socket(int af, int style, int protocol);
    /* The dup function on Windows works only on file descriptors, not socket
       handles. This function accomplishes the same thing for sockets. */
    int dup_socket(int sd);
    int unblock_socket(int sd);
    int block_socket(int sd);
    int socket_bindtodevice(int sd, const char* device);

    /* CRC32 Cyclic Redundancy Check */
    unsigned long nbase_crc32(unsigned char* buf, int len);
    /* CRC32C Cyclic Redundancy Check (Castagnoli) */
    unsigned long nbase_crc32c(unsigned char* buf, int len);
    /* Adler32 Checksum */
    unsigned long nbase_adler32(unsigned char* buf, int len);

    double tval2secs(const char* tspec);
    long tval2msecs(const char* tspec);
    const char* tval_unit(const char* tspec);

    //int fselect(int s, fd_set* rmaster, fd_set* wmaster, fd_set* emaster, struct timeval* tv);

    char* hexdump(const u8* cp, u32 length);

    char* executable_path(const char* argv0);

    /* addrset management functions and definitions */
    /* A set of addresses. Used to match against allow/deny lists. */
    struct addrset;

    void nbase_set_log(void (*log_user_func)(const char*, ...), void (*log_debug_func)(const char*, ...));
    struct addrset* addrset_new();
    extern void addrset_free(struct addrset* set);
    extern void addrset_print(FILE* fp, const struct addrset* set);
    extern int addrset_add_spec(struct addrset* set, const char* spec, int af, int dns);
    extern int addrset_add_file(struct addrset* set, FILE* fd, int af, int dns);
    extern int addrset_contains(const struct addrset* set, const struct sockaddr* sa);

#ifndef STDIN_FILENO
#define STDIN_FILENO 0
#endif

#ifndef STDOUT_FILENO
#define STDOUT_FILENO 1
#endif

#ifndef STDERR_FILENO
#define STDERR_FILENO 2
#endif

//#include "nbase_ipv6.h"

#ifdef __cplusplus
}
#endif

#endif /* NBASE_H */

struct eth_handle {
    int fd;
    char device[16];
};

typedef struct eth_handle eth_t;

struct eth_nfo {
    char srcmac[6];
    char dstmac[6];
    eth_t* ethsd;
    char devname[16];
};