#pragma once

#include "RubyAndShit.h"

#include "rcapdissector.h"

#ifdef USE_LOOKASIDE_LIST
#include "RubyAllocator.h"
#include "ProtocolTreeNodeLookasideList.h"
#endif

class CapFile
{
public:
	static VALUE createClass();

	static void initPacketCapture();
	static void deinitPacketCapture();

#ifdef USE_LOOKASIDE_LIST
	ProtocolTreeNodeLookasideList& getNodeLookasideList() { return _nodeLookaside; }
#endif

private:
	CapFile(void);
	virtual ~CapFile(void);

	/*@ Packet capture helper methods */
	static const char* buildCfOpenErrorMessage(int err, 
		gchar *err_info, 
		gboolean for_writing,
		int file_type);

	/*@ Methods implementing the CapFile Ruby object methods */
	static void free(void* p);
	static VALUE alloc(VALUE klass);
	static VALUE initialize(VALUE self, VALUE capfile);
	static VALUE init_copy(VALUE copy, VALUE orig);

	static VALUE set_preference(VALUE klass, VALUE name, VALUE value);
	static VALUE set_wlan_decryption_key(VALUE klass, VALUE key);
	static VALUE set_wlan_decryption_keys(VALUE klass, VALUE keys);

	static VALUE set_display_filter(VALUE self, VALUE filter); 

	static VALUE each_packet(VALUE self);

    static VALUE close_capture_file(VALUE self);

        static VALUE deinitialize();

	/*@ Instance methods that actually perform the CapFile-specific work */
	void openCaptureFile(VALUE capFileName);
	void closeCaptureFile();
	void setDisplayFilter(VALUE filter);
	void eachPacket();

	static void setPreference(const char* name, const char* value);
	static void setWlanDecryptionKey(VALUE key);
	static void setWlanDecryptionKeys(VALUE keys);

        void setupColumns();

        static gint* COLUMNS;
        static gint NUM_COLUMNS;

	VALUE _self;
	capture_file _cf;
#ifdef USE_LOOKASIDE_LIST
	RubyAllocator _allocator;
	ProtocolTreeNodeLookasideList _nodeLookaside;
#endif
};
