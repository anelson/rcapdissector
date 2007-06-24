#pragma once

#include <map>
#include <string>

#include "RubyAndShit.h"

#include "rcapdissector.h"

class Packet
{
public:
	static VALUE createClass();

	/** Gets the next packet from a capfile object, returning false if the end of the capfile is reached */
	static gboolean getNextPacket(VALUE capFileObject, capture_file& cf, VALUE& packet);

	epan_dissect_t* getEpanDissect() { return _edt; }
private:
	typedef struct _NODE_STRUCT {
		const gchar* name;
		proto_node* node;
		VALUE fieldObject;
	} NODE_STRUCT;

	/** Contains fields keyed by their name */
	typedef std::multimap<std::string, NODE_STRUCT*> NodeNameMap;

	/** Contains nodes keyed by their parent node's memory address */
	typedef std::multimap<guint64, NODE_STRUCT*> NodeParentMap;

	Packet();
	virtual ~Packet(void);

	const Packet& operator=(const Packet&) {
		//TODO: Implement
		return *this;
	}

	/** Applies whatever filter is outstanding, and if packet passes filter, creates a Ruby Packet object 
	and its corresponding native object */
	static VALUE processPacket(VALUE capFileObject, capture_file& cf, gint64 offset);

	/*@ Packet capture helper methods */
	static void fillInFdata(frame_data *fdata, capture_file& cf,
				  const struct wtap_pkthdr *phdr, gint64 offset);
	static void clearFdata(frame_data *fdata);

	/*@ Methods implementing the Packet Ruby object methods */
	static void free(void* p);
	static void mark(void* p);
	static VALUE alloc(VALUE klass);
	static VALUE initialize(VALUE self, VALUE capFileObject);
	static VALUE init_copy(VALUE copy, VALUE orig);

	static VALUE field_exists(VALUE self, VALUE fieldName);
	static VALUE descendant_field_exists(VALUE self, VALUE parentField, VALUE fieldName);
	static VALUE find_first_field(VALUE self, VALUE fieldName);
	static VALUE each_field(int argc, VALUE* argv, VALUE self);
	static VALUE find_first_descendant_field(VALUE self, VALUE parentField, VALUE fieldName);
	static VALUE each_descendant_field(int argc, VALUE* argv, VALUE self);

	/*@ Instance methods that actually perform the Packet-specific work */
	void buildPacket();
	static void addNodeThunk(proto_node *node, gpointer data);
	void addNode(proto_node* node);
	VALUE getRubyFieldObjectForField(NODE_STRUCT& node);
	void mark();
	VALUE fieldExists(VALUE fieldName);
	VALUE descendantFieldExists(VALUE fieldName, VALUE parentField);
	VALUE findFirstField(VALUE fieldName);
	VALUE eachField(int argc, VALUE* argv);
	VALUE findFirstDescendantField(VALUE parentField, VALUE fieldName);
	VALUE eachDescendantField(int argc, VALUE* argv);

	VALUE _self;
	epan_dissect_t* _edt;
	frame_data _frameData;
	wtap* _wth;
	capture_file* _cf;
	NodeNameMap _nodesByName;
	NodeParentMap _nodesByParent;
};
