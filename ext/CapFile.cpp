#include "CapFile.h"

#include "NativePacket.h"

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

    //Define the 'each_packet' method
    rb_define_method(klass,
                     "each_packet", 
					 reinterpret_cast<VALUE(*)(ANYARGS)>(CapFile::each_packet), 
					 0);

    //Define the 'capture_file' attribute reader
    rb_define_attr(klass,
                   "capture_file",
                   TRUE, 
                   FALSE);

	return klass;
}

void CapFile::initPacketCapture() {
    epan_init(register_all_protocols, 
              register_all_protocol_handoffs,
              failure_message, 
              open_failure_message, 
              read_failure_message);
    init_dissection();
}

void CapFile::deinitPacketCapture() {
    cleanup_dissection();
    epan_cleanup();
}

CapFile::CapFile(void) {
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

VALUE CapFile::each_packet(VALUE self) {
	CapFile* cf = NULL;

	Data_Get_Struct(self, CapFile, cf);

	cf->eachPacket();
	return self;
}

void CapFile::openCaptureFile(VALUE capFileName) {
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
    rb_raise(g_capfile_error_class, err_msg);
}

void CapFile::closeCaptureFile() {
    if (_cf.wth) {
		::wtap_close(_cf.wth);
    }

    if (_cf.filename) {
		::g_free(_cf.filename);
    }

    memset(&_cf, 0, sizeof(_cf));
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
	}
}
