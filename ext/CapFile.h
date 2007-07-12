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
	static VALUE each_packet(VALUE self);

	/*@ Instance methods that actually perform the CapFile-specific work */
	void openCaptureFile(VALUE capFileName);
	void closeCaptureFile();
	void eachPacket();

	VALUE _self;
	capture_file _cf;
#ifdef USE_LOOKASIDE_LIST
	RubyAllocator _allocator;
	ProtocolTreeNodeLookasideList _nodeLookaside;
#endif
};
