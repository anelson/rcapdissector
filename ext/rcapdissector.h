#pragma once

#include "RubyAndShit.h"

#ifdef __cplusplus
extern "C" {
#endif

extern VALUE g_packet_class;
extern VALUE g_protocol_class;
extern VALUE g_field_class;
extern VALUE g_field_query_class;
extern VALUE g_capfile_error_class;
extern VALUE g_field_doesnt_match_error_class;

extern VALUE g_add_element_func;
extern VALUE g_at_func;

extern VALUE g_cap_dissector_module;
extern VALUE g_cap_file_class;
extern VALUE g_native_pointer_class;

extern ID g_id_call;

#ifdef __cplusplus
}
#endif

