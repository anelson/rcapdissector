#pragma once

#include "RubyAndShit.h"
#include "rcapdissector.h"

/** A pure native (no Ruby) wrapper around the wireshark proto_node structure, which extracts
name, value, display name, and display value information from the structure on an ad-hoc basis */
class ProtocolTreeNode
{
public:
	ProtocolTreeNode(VALUE packet, epan_dissect_t* edt, guint ordinal, proto_node* node, ProtocolTreeNode* parentNode);
	~ProtocolTreeNode(void);

	const gchar* getName();
	const gchar* getDisplayName();
	const guchar* getValue();

	const gchar* getDisplayValue();

	guint getFieldLength() const { return _length; }
	guint getPosition() const { return _position; }

	gboolean getIsProtocolNode();

	/** Gets (or creates if not already created) the Ruby Field object representing this protocol node */
	VALUE getFieldObject();

	/** Returns the Ruby Field object if it exists, otherwise returns Qnil */
	VALUE peekFieldObject() const { return _fieldObject; }

	proto_node* getProtoNode() const { return _node; }

	ProtocolTreeNode* getParentNode() const { return _parentNode; }

	guint getOrdinal() const { return _ordinal; }

private:
	/** The name of this node, like 'tcp' or 'wlan.bssid' */
	const gchar* _name;

	/** The display name of this node, if it has one, else NULL */
	const gchar* _displayName;

	/** Flag indicates if the display name has been computed yet */
	gboolean _displayNameComputed;

	/** THe raw binary value of this node if it has one, else NULL */
	const guchar* _value;

	/** Flag indicates if the value has been computed yet */
	gboolean _valueComputed;

	/** The display value of this node or NULL */
	const gchar* _displayValue;

	/** Flag indicates if the display value has been computed yet */
	gboolean _displayValueComputed;

	/** The length of this node's value in the frame */
	guint _length;

	/** The byte offset of this node's value in the frame */
	guint _position;

	/** True if this is a protocol node; false if it's a field node */
	gboolean _isProtocol;

	/** THe ordinal position of this field within the packet */
	guint _ordinal;

	/** THe wireshark proto_node object that this object wraps */
	proto_node* _node;

	epan_dissect_t* _edt;

	ProtocolTreeNode* _parentNode;

	/** The Ruby Packet object from which this node came.  Used only to create a ruby Field object for this node */
	VALUE _packet;

	/** If a Ruby Field object has been created to wrap this node, it's stored here, else Qnil */
	VALUE _fieldObject;

	/** The buffer which will store the node's display name if it's not embedded in the frame buffer data */
	gchar _displayNameBuffer[ITEM_LABEL_LENGTH];

	const guchar* getValueForField(field_info* fi);
};
