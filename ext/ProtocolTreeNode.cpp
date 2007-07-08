#include "ProtocolTreeNode.h"

#include "Field.h"

//Need some dissector constants
extern "C" {
#include "epan\dissectors\packet-frame.h"
#include "epan\dissectors\packet-data.h"
}

ProtocolTreeNode::ProtocolTreeNode(VALUE packet, epan_dissect_t* edt, guint ordinal, proto_node* node, ProtocolTreeNode* parentNode)
{
	_name = NULL;
	_displayName = NULL;
	_displayNameComputed = FALSE;
	_value = NULL;
	_valueComputed = FALSE;
	_displayValue = NULL;
	_displayValueComputed = FALSE;
	_length = 0;
	_position = 0;
	_isProtocol = FALSE;
	_edt = edt;
	_ordinal = ordinal;
	_node = node;
	_parentNode = parentNode;
	_packet = packet;
	_fieldObject = Qnil;

	//Pre-compute the node name
	field_info	*fi = PITEM_FINFO(node);
	
	if (fi->hfinfo->id == hf_text_only) {
		//Text only node; no name
		_name = "";
	} else if (fi->hfinfo->id == proto_data) {
		//Data node.  we'll call it 'data'
		_name = "data";
	} else {
		//A normal protocol or field node
		_name = fi->hfinfo->abbrev;
	}

	//Ditto for length and pos
	_length = fi->length;
	_position = fi->start;

	//FIgure out if this is a protocol or a field
	/* Text label. It's printed as a field with no name. */
	if (fi->hfinfo->id == hf_text_only) {
		_isProtocol = FALSE;
	}
	/* Uninterpreted data, i.e., the "Data" protocol, is
	 * printed as a field instead of a protocol. */
	else if (fi->hfinfo->id == proto_data) {
		_isProtocol = FALSE;
	}
	/* Normal protocols and fields */
	else {
		if (fi->hfinfo->type == FT_PROTOCOL) {
			_isProtocol = TRUE;
		}
		else {
			_isProtocol = FALSE;
		}
	}
}

ProtocolTreeNode::~ProtocolTreeNode(void)
{
}

const gchar* ProtocolTreeNode::getName() {
	return _name;
}

const gchar* ProtocolTreeNode::getDisplayName()  {
	if (!_displayNameComputed) {
		//Compute a display name
		field_info	*fi = PITEM_FINFO(_node);

		/* Text label. It's printed as a field with no name. */
		if (fi->hfinfo->id == hf_text_only) {
			_displayName = NULL;
		}
		/* Uninterpreted data, i.e., the "Data" protocol, is
		 * printed as a field instead of a protocol. */
		else if (fi->hfinfo->id == proto_data) {
			_displayName = NULL;
		}
		/* Normal protocols and fields */
		else {
			if (fi->rep) {
				_displayName = fi->rep->representation;
			}
			else {
				::proto_item_fill_label(fi, _displayNameBuffer);
				_displayName = _displayNameBuffer;
			}
		}

		_displayNameComputed = TRUE;
	}

	return _displayName;
}

const guchar* ProtocolTreeNode::getValue() {
	if (!_valueComputed) {
		field_info	*fi = PITEM_FINFO(_node);

		/* Text label. It's printed as a field with no name. */
		if (fi->hfinfo->id == hf_text_only) {
			_value = getValueForField(fi);
		}
		/* Uninterpreted data, i.e., the "Data" protocol, is
		 * printed as a field instead of a protocol. */
		else if (fi->hfinfo->id == proto_data) {
			_value = getValueForField(fi);
		}
		/* Normal protocols and fields */
		else {
			/* show, value, and unmaskedvalue attributes */
			switch (fi->hfinfo->type)
			{
			case FT_PROTOCOL:
				break;
			case FT_NONE:
				break;
			default:
				/*
				 * XXX - should we omit "value" for any fields?
				 * What should we do for fields whose length is 0?
				 * They might come from a pseudo-header or from
				 * the capture header (e.g., time stamps), or
				 * they might be generated fields.
				 */
				if (fi->length > 0) {
					_value = getValueForField(fi);
				}
			}
		}
		_valueComputed = TRUE;
	}

	return _value;
}

const gchar* ProtocolTreeNode::getDisplayValue() {
	if (!_displayValueComputed) {
		field_info	*fi = PITEM_FINFO(_node);

		/* Text label. It's printed as a field with no name. */
		if (fi->hfinfo->id == hf_text_only) {
			if (fi->rep) {
				_displayValue = fi->rep->representation;
			}
			else {
				_displayValue = "";
			}
		}
		/* Uninterpreted data, i.e., the "Data" protocol, is
		 * printed as a field instead of a protocol. */
		else if (fi->hfinfo->id == proto_data) {
			_displayValue = NULL;
		}
		/* Normal protocols and fields */
		else {
			/* show, value, and unmaskedvalue attributes */
			char		*dfilter_string;
			size_t		chop_len;
			switch (fi->hfinfo->type)
			{
			case FT_PROTOCOL:
				break;
			case FT_NONE:
				break;
			default:
				/* XXX - this is a hack until we can just call
				 * fvalue_to_string_repr() for *all* FT_* types. */
				/* NB: proto_construct_match_selected_string does allocate memory, but it does it 
				in the context of the current packet dissector, thus there's no need to free it here as it 
				will be freed when the dissector is cleaned up */
				dfilter_string = ::proto_construct_match_selected_string(fi,
					_edt);
				if (dfilter_string != NULL) {
					chop_len = ::strlen(fi->hfinfo->abbrev) + 4; /* for " == " */

					/* XXX - Remove double-quotes. Again, once we
					 * can call fvalue_to_string_repr(), we can
					 * ask it not to produce the version for
					 * display-filters, and thus, no
					 * double-quotes. */
					if (dfilter_string[strlen(dfilter_string)-1] == '"') {
						dfilter_string[strlen(dfilter_string)-1] = '\0';
						chop_len++;
					}

					_displayValue = &dfilter_string[chop_len];
				}
			}
		}
		_displayValueComputed = TRUE;
	}

	return _displayValue;
}

gboolean ProtocolTreeNode::getIsProtocolNode() {
	return _isProtocol;
}


VALUE ProtocolTreeNode::getFieldObject() {
	if (_fieldObject == Qnil) {
		//Need to create the field object
		_fieldObject = Field::createField(_packet,
			this);
	}

	return _fieldObject;
}

const guchar* ProtocolTreeNode::getValueForField(field_info* fi) {
	if (fi->length > tvb_length_remaining(fi->ds_tvb, fi->start)) {
		rb_raise(g_capfile_error_class, "field length invalid");
	}
	
	GSList *src_le;
	data_source *src;
	tvbuff_t *src_tvb;
	gint length, tvbuff_length;

	for (src_le = _edt->pi.data_src; src_le != NULL; src_le = src_le->next) {
		src = (data_source*)src_le->data;
		src_tvb = src->tvb;
		if (fi->ds_tvb == src_tvb) {
			/*
			 * Found it.
			 *
			 * XXX - a field can have a length that runs past
			 * the end of the tvbuff.  Ideally, that should
			 * be fixed when adding an item to the protocol
			 * tree, but checking the length when doing
			 * that could be expensive.  Until we fix that,
			 * we'll do the check here.
			 */
			tvbuff_length = tvb_length_remaining(src_tvb,
			    fi->start);
			if (tvbuff_length < 0) {
				return NULL;
			}
			length = fi->length;
			if (length > tvbuff_length)
				length = tvbuff_length;
			return tvb_get_ptr(src_tvb, fi->start, length);
		}
	}
	g_assert_not_reached();
	return NULL;	/* not found */
}

