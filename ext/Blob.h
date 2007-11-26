#pragma once

#include "RubyAndShit.h"

#include "rcapdissector.h"

/** Ruby extension object that wraps the wireshark data_source, which is effectively a named blob
where the blob contents are exposed as tvb's, which are roughly akin to the mbuf's in the BSD and Linux
network stacks.

For applications that need access to the raw packet, or (most likely) the reassembled payload of a number of
TCP segments, this type comes in handy */
class Blob
{
public:
	static VALUE createClass();

	/** Creates a new Blob object */
	static VALUE createBlob(VALUE packet, data_source* ds);

	VALUE getRubyWrapper() const { return _self; }

	const data_source* getDataSource() const { return _ds; }

private:
	Blob(void);
	virtual ~Blob(void);
	
	/*@ Methods implementing the Blob Ruby object methods */
	static void free(void* p);
	static void mark(void* p);
	static VALUE alloc(VALUE klass);
	static VALUE initialize(VALUE self, VALUE packetObject);
	static VALUE init_copy(VALUE copy, VALUE orig);

	static VALUE name(VALUE self);
	static VALUE value(VALUE self);
	static VALUE length(VALUE self);

	/*@ Instance methods that actually perform the Blob-specific work */
	void mark();

public:
	//Public to avoid duplicating the Ruby wrapper around the name string when adding to the hash
	VALUE getName();

private:
	VALUE getValue();
	VALUE getLength();
	
	VALUE _self;

	data_source* _ds;

	VALUE _rubyName;
	VALUE _rubyValue;
	VALUE _rubyLength;
};
