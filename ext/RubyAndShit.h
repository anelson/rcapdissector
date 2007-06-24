#pragma once

//Include the Ruby and Wireshark and Windows stuff with all the nasty warnings hidden
#pragma warning(push)
#pragma warning(disable : 4312) //'type cast' : conversion from 'VALUE' to 'RBasic *' of greater size
#pragma warning(disable : 4005) //warning C4005: 'strcasecmp' : macro redefinition

#include <winsock2.h>
#include <windows.h>

#include "ruby.h"


//LAME: Ruby's win32\win32.h file has this lovely little sure-to-please nugget on or about line 122:
// #define write(f, b, s)		rb_w32_write(f, b, s)
//
//Amazingly, other source files want to use the word 'write' in various places, not always as a function call.
//This #define fucks that, hard.  Elide it.  Ditto for 'read', duh.
#ifdef write
#undef write //fuck you ruby
#endif
#ifdef read
#undef read
#endif


#ifdef __cplusplus
extern "C" {
#endif

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <locale.h>
#include <limits.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <errno.h>

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#include <signal.h>

#ifdef HAVE_SYS_STAT_H
# include <sys/stat.h>
#endif

#ifdef NEED_STRERROR_H
#include "strerror.h"
#endif

#ifdef NEED_GETOPT_H
#include "getopt.h"
#endif

#include <glib.h>
#include <epan/epan.h>
#include <epan/filesystem.h>
#include <epan/privileges.h>
#include <wiretap/file_util.h>

#include "globals.h"
#include <epan/timestamp.h>
#include <epan/packet.h>
#include "file.h"
#include "disabled_protos.h"
#include <epan/prefs.h>
#include <epan/column.h>
#include "print.h"
#include <epan/addr_resolv.h>
#include "util.h"
#include "clopts_common.h"
#include "cmdarg_err.h"
#include "version_info.h"
#include <epan/conversation.h>
#include <epan/plugins.h>
#include "register.h"
#include "conditions.h"
#include "capture_stop_conditions.h"
#include "ringbuffer.h"
#include "capture_ui_utils.h"
#include <epan/epan_dissect.h>
#include <epan/tap.h>
#include <epan/stat_cmd_args.h>
#include <epan/timestamp.h>
#include <epan/ex-opt.h>

#ifdef HAVE_LIBPCAP
#include <pcap.h>
#include <setjmp.h>
#include "capture-pcap-util.h"
#include "pcapio.h"
#include <wiretap/wtap-capture.h>
#ifdef _WIN32
#include "capture-wpcap.h"
#include "capture_errs.h"
#endif /* _WIN32 */
#include "capture.h"
#include "capture_loop.h"
#include "capture_sync.h"
#endif /* HAVE_LIBPCAP */
#include "epan/emem.h"
#include "log.h"
#include <epan/funnel.h>

#ifdef __cplusplus
}
#endif

#pragma warning(pop)

//Data_Get_Struct causes warning 4312 within code, so leave this warning disabled
//dotto 4127
//glib\gmessages.h causes warning 4505 alot

#pragma warning(disable : 4312) //'type cast' : conversion from 'VALUE' to 'RBasic *' of greater size
#pragma warning(disable : 4127) // conditional expression is constant
#pragma warning(disable : 4505) // 'g_error' : unreferenced local function has been removed