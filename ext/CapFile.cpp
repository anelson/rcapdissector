#include "CapFile.h"

#include <sstream>

#include "NativePacket.h"

/** copied from Wireshark, epan\dissectors\packet-ieee80211.c */
#define MAX_ENCRYPTION_KEYS 64

/**@ Static callbacks passed to EPAN; not meant to do anything */
/*
 * Open/create errors are reported with an console message in TShark.
 */
static void
open_failure_message(const char *filename, int err, gboolean for_writing) {
    fprintf(stderr, "rcapdissector: ");
    fprintf(stderr, file_open_error_message(err, for_writing), filename);
    fprintf(stderr, "\n");
}

/*
 * General errors are reported with an console message in TShark.
 */
static void
failure_message(const char *msg_format, va_list ap) {
    fprintf(stderr, "rcapdissector: ");
    vfprintf(stderr, msg_format, ap);
    fprintf(stderr, "\n");
}

/*
 * Read errors are reported with an console message in TShark.
 */
static void
read_failure_message(const char *filename, int err) {
    cmdarg_err("An error occurred while reading from the file \"%s\": %s.",
               filename, strerror(err));
}

/****************************************************************************************************************/
/* indication report "dummies", needed for capture_loop.c */

#ifdef HAVE_LIBPCAP

/** Report a new capture file having been opened. */
void
report_new_capture_file(const char *) {
    /* shouldn't happen */
    g_assert_not_reached();
}

/** Report a number of new packets captured. */
void
report_packet_count(int ) {
    /* shouldn't happen */
    g_assert_not_reached();
}

/** Report the packet drops once the capture finishes. */
void
report_packet_drops(int ) {
    /* shouldn't happen */
    g_assert_not_reached();
}

/** Report an error in the capture. */
void
report_capture_error(const char *errmsg, const char *secondary_error_msg) {
    cmdarg_err(errmsg);
    cmdarg_err_cont(secondary_error_msg);
}

/** Report an error with a capture filter. */
void
report_cfilter_error(const char *cfilter, const char *errmsg) {

    cmdarg_err(
              "Invalid capture filter: \"%s\"!\n"
              "\n"
              "That string isn't a valid capture filter (%s).\n"
              "See the User's Guide for a description of the capture filter syntax.",
              cfilter, errmsg);
}

#endif /* HAVE_LIBPCAP */


/****************************************************************************************************************/
/* signal pipe "dummies", needed for capture_loop.c */

#ifdef HAVE_LIBPCAP

    #ifdef _WIN32
gboolean
signal_pipe_check_running(void) {
    /* currently, no check required */
    return TRUE;
}
    #endif  /* _WIN32 */

#endif /* HAVE_LIBPCAP */

/*
 * Report an error in command-line arguments.
 */
void
cmdarg_err(const char *fmt, ...) {
    va_list ap;

    va_start(ap, fmt);
    fprintf(stderr, "rcapdissector: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
}

/*
 * Report additional information for an error in command-line arguments.
 */
void
cmdarg_err_cont(const char *fmt, ...) {
    va_list ap;

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
}


VALUE CapFile::createClass() {
    //Define the 'CapFile' class
	VALUE klass = rb_define_class_under(g_cap_dissector_module, "CapFile", rb_cObject);
	rb_define_alloc_func(klass, CapFile::alloc);

    //Define the 'initialize' method
    rb_define_method(klass,
                     "initialize", 
					 reinterpret_cast<VALUE(*)(ANYARGS)>(CapFile::initialize), 
					 1);

    rb_define_singleton_method(klass,
                     "set_preference", 
					 reinterpret_cast<VALUE(*)(ANYARGS)>(CapFile::set_preference), 
					 2);

    rb_define_singleton_method(klass,
                     "set_wlan_decryption_key", 
					 reinterpret_cast<VALUE(*)(ANYARGS)>(CapFile::set_wlan_decryption_key), 
					 1);

    rb_define_singleton_method(klass,
                     "set_wlan_decryption_keys", 
					 reinterpret_cast<VALUE(*)(ANYARGS)>(CapFile::set_wlan_decryption_keys), 
					 1);

    rb_define_method(klass,
                     "set_display_filter", 
					 reinterpret_cast<VALUE(*)(ANYARGS)>(CapFile::set_display_filter), 
					 1);

    //Define the 'each_packet' method
    rb_define_method(klass,
                     "each_packet", 
					 reinterpret_cast<VALUE(*)(ANYARGS)>(CapFile::each_packet), 
					 0);

    //Define the 'close' method
    rb_define_method(klass,
                     "close", 
					 reinterpret_cast<VALUE(*)(ANYARGS)>(CapFile::close_capture_file), 
					 0);

    //Define the 'capture_file' attribute reader
    rb_define_attr(klass,
                   "capture_file",
                   TRUE, 
                   FALSE);

	//Define some const values for useful TCP prefs
	::rb_define_const(klass, "PREF_TCP_SHOW_SUMMARY", ::rb_str_new2("tcp.summary_in_tree"));
	::rb_define_const(klass, "PREF_TCP_CHECK_CHECKSUM", ::rb_str_new2("tcp.check_checksum"));
	::rb_define_const(klass, "PREF_TCP_DESEGMENT_STREAMS", ::rb_str_new2("tcp.desegment_tcp_streams"));
	::rb_define_const(klass, "PREF_TCP_ANALYZE_SEQUENCE_NUMBERS", ::rb_str_new2("tcp.analyze_sequence_numbers"));
	::rb_define_const(klass, "PREF_TCP_RELATIVE_SEQUENCE_NUMBERS", ::rb_str_new2("tcp.relative_sequence_numbers"));
	::rb_define_const(klass, "PREF_TCP_TRY_HEURISTIC_FIRST", ::rb_str_new2("tcp.try_heuristic_first"));

    //Define some HTTP refs 
	::rb_define_const(klass, "PREF_HTTP_DESEGMENT_HEADERS", ::rb_str_new2("http.desegment_headers"));
	::rb_define_const(klass, "PREF_HTTP_DESEGMENT_BODY", ::rb_str_new2("http.desegment_body"));
	::rb_define_const(klass, "PREF_HTTP_DECHUNK_BODY", ::rb_str_new2("http.dechunk_body"));
	::rb_define_const(klass, "PREF_HTTP_DECOMPRESS_BODY", ::rb_str_new2("http.decompress_body"));

	//Initialize some prefs to reasonable defaults
	setPreference("tcp.summary_in_tree", "true");
	setPreference("tcp.check_checksum", "false");
	setPreference("tcp.desegment_tcp_streams", "true");
	setPreference("tcp.analyze_sequence_numbers", "true");
	setPreference("tcp.relative_sequence_numbers", "true");
	setPreference("tcp.try_heuristic_first", "false");

	return klass;
}

void CapFile::initPacketCapture() {
    epan_init(register_all_protocols, 
              register_all_protocol_handoffs,
              NULL, NULL,
              failure_message, 
              open_failure_message, 
              read_failure_message);
    init_dissection();
}

void CapFile::deinitPacketCapture() {
    cleanup_dissection();
    epan_cleanup();
}

CapFile::CapFile(void)
#ifdef USE_LOOKASIDE_LIST
	//These initial/max numbers are derived imperically; typical wlan captures contain no more than 187 fields
	//so these numbers should minimize heap operations while also keeping memory consumption at the low end
	: _nodeLookaside(_allocator, 200, 500)
#endif
{
	::memset(&_cf, 0, sizeof(_cf));
}

CapFile::~CapFile(void) {
	closeCaptureFile();
}

const char* CapFile::buildCfOpenErrorMessage(int err, 
		gchar *err_info, 
		gboolean for_writing,
		int file_type) {
    const char *errmsg;
    static char errmsg_errno[1024+1];

    if (err < 0) {
        /* Wiretap error. */
        switch (err) {
        
        case WTAP_ERR_NOT_REGULAR_FILE:
            errmsg = "The file \"%s\" is a \"special file\" or socket or other non-regular file.";
            break;

        case WTAP_ERR_FILE_UNKNOWN_FORMAT:
            /* Seen only when opening a capture file for reading. */
            errmsg = "The file \"%s\" isn't a capture file in a format TShark understands.";
            break;

        case WTAP_ERR_UNSUPPORTED:
            /* Seen only when opening a capture file for reading. */
            g_snprintf(errmsg_errno, sizeof(errmsg_errno),
                       "The file \"%%s\" isn't a capture file in a format TShark understands.\n"
                       "(%s)", err_info);
            g_free(err_info);
            errmsg = errmsg_errno;
            break;

        case WTAP_ERR_CANT_WRITE_TO_PIPE:
            /* Seen only when opening a capture file for writing. */
            g_snprintf(errmsg_errno, sizeof(errmsg_errno),
                       "The file \"%%s\" is a pipe, and %s capture files can't be "
                       "written to a pipe.", wtap_file_type_string(file_type));
            errmsg = errmsg_errno;
            break;

        case WTAP_ERR_UNSUPPORTED_FILE_TYPE:
            /* Seen only when opening a capture file for writing. */
            errmsg = "TShark doesn't support writing capture files in that format.";
            break;

        case WTAP_ERR_UNSUPPORTED_ENCAP:
            if (for_writing)
                errmsg = "TShark can't save this capture in that format.";
            else {
                g_snprintf(errmsg_errno, sizeof(errmsg_errno),
                           "The file \"%%s\" is a capture for a network type that TShark doesn't support.\n"
                           "(%s)", err_info);
                g_free(err_info);
                errmsg = errmsg_errno;
            }
            break;

        case WTAP_ERR_ENCAP_PER_PACKET_UNSUPPORTED:
            if (for_writing)
                errmsg = "TShark can't save this capture in that format.";
            else
                errmsg = "The file \"%s\" is a capture for a network type that TShark doesn't support.";
            break;

        case WTAP_ERR_BAD_RECORD:
            /* Seen only when opening a capture file for reading. */
            g_snprintf(errmsg_errno, sizeof(errmsg_errno),
                       "The file \"%%s\" appears to be damaged or corrupt.\n"
                       "(%s)", err_info);
            g_free(err_info);
            errmsg = errmsg_errno;
            break;

        case WTAP_ERR_CANT_OPEN:
            if (for_writing)
                errmsg = "The file \"%s\" could not be created for some unknown reason.";
            else
                errmsg = "The file \"%s\" could not be opened for some unknown reason.";
            break;

        case WTAP_ERR_SHORT_READ:
            errmsg = "The file \"%s\" appears to have been cut short"
                     " in the middle of a packet or other data.";
            break;

        case WTAP_ERR_SHORT_WRITE:
            errmsg = "A full header couldn't be written to the file \"%s\".";
            break;

        default:
            g_snprintf(errmsg_errno, sizeof(errmsg_errno),
                       "The file \"%%s\" could not be %s: %s.",
                       for_writing ? "created" : "opened",
                       wtap_strerror(err));
            errmsg = errmsg_errno;
            break;
        }
    } else
        errmsg = file_open_error_message(err, for_writing);
    return errmsg;
}

/*@ Methods implementing the CapFile Ruby object methods */
void CapFile::free(void* p) {
	CapFile* cf = reinterpret_cast<CapFile*>(p);
	delete cf;
}

VALUE CapFile::alloc(VALUE klass) {
	//Allocate memory for the CapFile instance which will be tied to this Ruby object
	VALUE wrappedCf;
	CapFile* cf = new CapFile();

	wrappedCf = Data_Wrap_Struct(klass, 0, CapFile::free, cf);

	return wrappedCf;
}

VALUE CapFile::initialize(VALUE self, VALUE capfile) {
	CapFile* cf = NULL;

    //Save off the capfile name
    rb_iv_set(self, "@capture_file", capfile);

	Data_Get_Struct(self, CapFile, cf);

	cf->_self = self;
	cf->openCaptureFile(capfile);

    return self;
}

VALUE CapFile::init_copy(VALUE copy, VALUE orig) {
	//Copy this object to a new one.  Open the cap file again
	CapFile* cfCopy = NULL;
	CapFile* cfOrig = NULL;
	VALUE origCapFile;

	if (copy == orig) {
		return copy;
	}
	
	if(TYPE(orig)!=T_DATA ||
		RDATA(orig)->dfree!=(RUBY_DATA_FUNC)CapFile::free) {
		rb_raise(rb_eTypeError, "Wrong argument type");
	}

	Data_Get_Struct(copy, CapFile, cfCopy);
	Data_Get_Struct(orig, CapFile, cfOrig);

	origCapFile = rb_iv_get(orig, "@capture_file");

	cfCopy->_self = copy;
	cfCopy->openCaptureFile(origCapFile);

	return copy;
}

VALUE CapFile::set_preference(VALUE, VALUE name, VALUE value) {
	//Cast both name and value to strings and pass to Wireshark
	SafeStringValue(name);
	SafeStringValue(value);

	//Convert to C-style strings and call the overload
	setPreference(RSTRING(name)->ptr,
		RSTRING(value)->ptr);

	return Qnil;
}

VALUE CapFile::set_wlan_decryption_key(VALUE, VALUE key) {
	CapFile::setWlanDecryptionKey(key);
	return Qnil;
}

VALUE CapFile::set_wlan_decryption_keys(VALUE, VALUE keys) {
	CapFile::setWlanDecryptionKeys(keys);
	return Qnil;
}

VALUE CapFile::set_display_filter(VALUE self, VALUE filter) {
	CapFile* cf = NULL;

	Data_Get_Struct(self, CapFile, cf);

	cf->setDisplayFilter(filter);
	return self;
}

VALUE CapFile::each_packet(VALUE self) {
	CapFile* cf = NULL;

	Data_Get_Struct(self, CapFile, cf);

	cf->eachPacket();
	return self;
}

VALUE CapFile::close_capture_file(VALUE self) {
	CapFile* cf = NULL;

	Data_Get_Struct(self, CapFile, cf);

	cf->closeCaptureFile();
	return self;
}

void CapFile::openCaptureFile(VALUE capFileName) {
	//Apply any previously-set preferences
	prefs_apply_all();

    const char* name = RSTRING(capFileName)->ptr;

    wtap       *wth;
    gchar       *err_info;
    char        err_msg[2048+1];
    int         err;

    wth = wtap_open_offline(name, &err, &err_info, FALSE);
    if (wth == NULL)
        goto fail;

    /* The open succeeded.  Fill in the information for this file. */

    _cf.wth = wth;
    _cf.f_datalen = 0; /* not used, but set it anyway */

    /* Set the file name because we need it to set the follow stream filter.
       XXX - is that still true?  We need it for other reasons, though,
       in any case. */
    _cf.filename = g_strdup(name);

    /* Indicate whether it's a permanent or temporary file. */
    _cf.is_tempfile = FALSE;

    /* If it's a temporary capture buffer file, mark it as not saved. */
    _cf.user_saved = TRUE;

    _cf.cd_t      = static_cast<guint16>(wtap_file_type(_cf.wth));
    _cf.count     = 0;
    _cf.drops_known = FALSE;
    _cf.drops     = 0;
    _cf.snap      = wtap_snapshot_length(_cf.wth);
    if (_cf.snap == 0) {
        /* Snapshot length not known. */
        _cf.has_snap = FALSE;
        _cf.snap = WTAP_MAX_PACKET_SIZE;
    } else
        _cf.has_snap = TRUE;
    nstime_set_zero(&_cf.elapsed_time);

    return;

    fail:
    g_snprintf(err_msg, 
		sizeof err_msg,
		buildCfOpenErrorMessage(err, err_info, FALSE, _cf.cd_t), name);
    rb_raise(g_wtapcapfile_error_class, err_msg, err);
}

void CapFile::closeCaptureFile() {
    if (_cf.wth) {
		::wtap_close(_cf.wth);
    }

    if (_cf.filename) {
		::g_free(_cf.filename);
    }

	if (_cf.rfcode != NULL) {
		dfilter_free(_cf.rfcode);
		_cf.rfcode = NULL;
	}

    memset(&_cf, 0, sizeof(_cf));

#ifdef USE_LOOKASIDE_LIST
	_nodeLookaside.emptyPool();
#endif
    
}
	
void CapFile::setDisplayFilter(VALUE filter) {
	if (NIL_P(filter)) {
		//Clear the filter
		_cf.rfcode = NULL;
	} else {
		SafeStringValue(filter);
		const gchar* rfilter = RSTRING(filter)->ptr;

		if (!::dfilter_compile(rfilter, &_cf.rfcode)) {
			std::string msg = "Error setting display filter: ";
			msg += dfilter_error_msg;
			::rb_raise(g_capfile_error_class,
				msg.c_str());
		}
	}
}

void CapFile::eachPacket() {
	rb_need_block();

	if (!rb_block_given_p()) {
		rb_raise(rb_eArgError, "each_packet must be invoked with a block");
	}


	//TODO: Move into this module
	VALUE packet = Qnil;
	while (Packet::getNextPacket(_self, _cf, packet)) {
		rb_yield(packet);
		/** Free up the resources for this packet so they can be used by the next one */
		Packet::freePacket(packet);
	}
}

void CapFile::setPreference(const char* name, const char* value) {
	//Build a string of the form name:value to pass to wireshark
	std::string pref = name;
	pref += ":";
	pref += value;

	//Pet peeve: fucktards that don't make their [in] arguments as const, and force me to
	//do it for them
	::prefs_set_pref_e result = ::prefs_set_pref(const_cast<char*>(pref.c_str()));
	if (result == ::PREFS_SET_OK) {
		return;
	} else {
		//An error of some kind
		std::stringstream msg;
		if (result == ::PREFS_SET_SYNTAX_ERR) {
			msg << "Syntax error setting '" << name << "' to '" << value << "'";
		} else if (result == ::PREFS_SET_NO_SUCH_PREF) {
			msg << "There is no such preference '" << name << "'";
		} else if (result == ::PREFS_SET_OBSOLETE) {
			msg << "The preference '" << name << "' is obsolete";
		} else {
			msg << "Got unrecognized return value " << result << " when setting '" << name << "' to '" << value << "'";
		}

		::rb_raise(g_capfile_error_class, msg.str().c_str());
	}
}

void CapFile::setWlanDecryptionKey(VALUE key) {
	//Special case of setWlanDecryptionKeys
	//Pass in an array of this one key
	if (NIL_P(key)) {
		setWlanDecryptionKeys(Qnil);
	} else {
		VALUE keys = ::rb_ary_new();
		::rb_ary_push(keys, key);

		setWlanDecryptionKeys(keys);
	}
}

void CapFile::setWlanDecryptionKeys(VALUE keys) {
	//keys should be a ruby Array of string values, each one representing a WEP decryption key
	char prefName[64];

	if (NIL_P(keys)) {
		//Disable WLAN decryption
		setPreference("wlan.enable_decryption", "false");
		return;
	}

	//Else, enable decryption and set up the keys
	setPreference("wlan.enable_decryption", "true");

	keys = ::rb_check_array_type(keys);
	for (int idx = 0; idx < RARRAY(keys)->len; idx++) {
		SafeStringValue(RARRAY(keys)->ptr[idx]);
	
		::snprintf(prefName,
			sizeof(prefName),
			"wlan.wep_key%d", idx + 1);

		setPreference(prefName, 
			RSTRING(RARRAY(keys)->ptr[idx])->ptr);
	}

	//TODO: Is there some way to null out the remaining key values?  It doesn't seem possible
	//using the high-level preference setting API we're using, since passing an empty string for a
	//preference value throws a syntax error.  Figure out some day.
}



