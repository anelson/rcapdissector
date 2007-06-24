#pragma once

#include "RubyAndShit.h"

#include "NativePacket.h"


class Field
{
public:
	static VALUE createClass();

	/** Creates a new Field object */
	static VALUE createField(VALUE packet, const gchar* fieldName, proto_node* node);

	proto_node* getProtoNode() { return _node; }
private:
	Field();
	virtual ~Field(void);

	const Field& operator=(const Field&) {
		//TODO: Implement
		return *this;
	}

	/**@ Packet-related helper methods */
	static const guchar* getValueForField(epan_dissect_t* edt, field_info *fi);


	/*@ Methods implementing the Field Ruby object methods */
	static void free(void* p);
	static void mark(void* p);
	static VALUE alloc(VALUE klass);
	static VALUE initialize(VALUE self, VALUE packetObject);
	static VALUE init_copy(VALUE copy, VALUE orig);
	static VALUE name(VALUE self);
	static VALUE display_name(VALUE self);
	static VALUE value(VALUE self);
	static VALUE display_value(VALUE self);
	static VALUE length(VALUE self);
	static VALUE position(VALUE self);

	/*@ Instance methods that actually perform the Field-specific work */
	void mark();
	void populateField();

	VALUE getName();
	VALUE getDisplayName();
	VALUE getValue();
	VALUE getDisplayValue();
	VALUE getLength();
	VALUE getPosition();

	VALUE _self;

	proto_node* _node;
	const gchar* _name;
	const guchar* _value;
	guint _length;
	guint _position;
	const gchar* _displayName;
	std::string _displayValue;
	gboolean _isProtocol;

	VALUE _rubyName;
	VALUE _rubyValue;
	VALUE _rubyLength;
	VALUE _rubyPosition;
	VALUE _rubyDisplayName;
	VALUE _rubyDisplayValue;

	Packet* _packet;

	gchar _displayNameBuffer[ITEM_LABEL_LENGTH];
};
