#include "adler32.c"
#include "compress.c"
#include "crc_folding.c"
#include "deflate.c"
#include "infback.c"
#include "inffast.c"
#include "inflate.c"
#include "inftrees.c"
#include "trees.c"
#include "uncompr.c"
#include "zutil.c"
#include "x86.c"
#include "slide_sse.c"
#include "match.c"
#include "deflate_medium.c"
#include "gzclose.c"
#include "gzlib.c"
#include "gzread.c"
#include "gzwrite.c"
#include "crc32.c"
int ZEXPORTVA gzprintf2(gzFile file, const char *format, ...)
{
    va_list va;
    int ret;

    va_start(va, format);
    ret = gzvprintf(file, format, va);
    va_end(va);
    return ret;
}
