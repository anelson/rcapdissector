#pragma once

#include "RubyAndShit.h"

#include "NativePacket.h"
#include "ProtocolTreeNode.h"


class Field
{
public:
	static VALUE createClass();

	/** Creates a new Field object */
	static VALUE createField(VALUE packet, ProtocolTreeNode* node);

	ProtocolTreeNode* getProtoNode() { return _node; }
private:
	Field();
	virtual ~Field(void);

	const Field& operator=(const Field&) {
		//TODO: Implement
		return *this;
	}


	/*@ Methods implementing the Field Ruby object methods */
	static void free(void* p);
	static void mark(void* p);
	static VALUE alloc(VALUE klass);
	static VALUE initialize(VALUE self, VALUE packetObject);
	static VALUE init_copy(VALUE copy, VALUE orig);
	static VALUE to_s(VALUE self);
	static VALUE name(VALUE self);
	static VALUE display_name(VALUE self);
	static VALUE value(VALUE self);
	static VALUE display_value(VALUE self);
	static VALUE length(VALUE self);
	static VALUE position(VALUE self);
	static VALUE flags(VALUE self);
	static VALUE is_protocol_node(VALUE self);
	static VALUE ordinal(VALUE self);

	static VALUE parent(VALUE self);
	static VALUE next_sibling(VALUE self);
	static VALUE each_child(VALUE self);

	static VALUE value_blob(VALUE self);
	static VALUE value_blob_offset(VALUE self);
	static VALUE value_blob_length(VALUE self);

	/*@ Instance methods that actually perform the Field-specific work */
	void mark();

	VALUE toString();
	VALUE getName();
	VALUE getDisplayName();
	VALUE getValue();
	VALUE getDisplayValue();
	VALUE getLength();
	VALUE getPosition();
	VALUE getFlags();
	VALUE getIsProtocolNode();
	VALUE getOrdinal();

	VALUE getParent();
	VALUE getNextSibling();
	VALUE eachChild();

	VALUE getValueBlob();
	VALUE getValueBlobOffset();
	VALUE getValueBlobLength();

	VALUE protocolTreeNodePtrToField(ProtocolTreeNode* node) {
		if (node) {
			return node->getFieldObject();
		} else {
			return Qnil;
		}
	}

	VALUE _self;

	ProtocolTreeNode* _node;

	VALUE _rubyName;
	VALUE _rubyValue;
	VALUE _rubyLength;
	VALUE _rubyPosition;
	VALUE _rubyDisplayName;
	VALUE _rubyDisplayValue;
	VALUE _rubyFlags;
	VALUE _rubyOrdinal;
	VALUE _rubyValueBlob;
	VALUE _rubyValueBlobOffset;
	VALUE _rubyValueBlobLength;

	Packet* _packet;

	gchar _displayNameBuffer[ITEM_LABEL_LENGTH];
};
