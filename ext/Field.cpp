#include "Field.h"

//Need some dissector constants
extern "C" {
#include "epan\dissectors\packet-frame.h"
#include "epan\dissectors\packet-data.h"
}

VALUE Field::createClass() {
    //Define the 'Field' class
	VALUE klass = rb_define_class_under(g_cap_dissector_module, "Field", rb_cObject);
	rb_define_alloc_func(klass, Field::alloc);

    //Define the 'initialize' method
    rb_define_method(klass,
                     "initialize", 
					 reinterpret_cast<VALUE(*)(ANYARGS)>(Field::initialize), 
					 1);

    //Define the 'packet' attribute reader
    rb_define_attr(klass,
                   "packet",
                   TRUE, 
                   FALSE);

    rb_define_method(klass,
                     "name", 
					 reinterpret_cast<VALUE(*)(ANYARGS)>(Field::name), 
					 0);
    rb_define_method(klass,
                     "display_name", 
					 reinterpret_cast<VALUE(*)(ANYARGS)>(Field::display_name), 
					 0);
    rb_define_method(klass,
                     "value", 
					 reinterpret_cast<VALUE(*)(ANYARGS)>(Field::value), 
					 0);
    rb_define_method(klass,
                     "display_value", 
					 reinterpret_cast<VALUE(*)(ANYARGS)>(Field::display_value), 
					 0);
    rb_define_method(klass,
                     "length", 
					 reinterpret_cast<VALUE(*)(ANYARGS)>(Field::length), 
					 0);
    rb_define_method(klass,
                     "position", 
					 reinterpret_cast<VALUE(*)(ANYARGS)>(Field::position), 
					 0);

	return klass;
}
	
VALUE Field::createField(VALUE packet, const gchar* fieldName, proto_node* node) {
	//Create the Field ruby object first
	VALUE argv[] = {
		packet
	};

	//Create a Field object for this packet
	VALUE field = rb_class_new_instance(_countof(argv),
										 argv,
										 g_field_class);

	//Get the wrapped Field object
	Field* nativeField = NULL;
	Data_Get_Struct(field, Field, nativeField);

	//Get the wrapped Packet object in the Ruby Packet object
	Packet* nativePacket = NULL;
	Data_Get_Struct(packet, Packet, nativePacket);

	nativeField->_self = field;
	nativeField->_packet = nativePacket;
	nativeField->_name = fieldName;
	nativeField->_node = node;

	nativeField->populateField();

	return field;
}

Field::Field() {
	_node = NULL;
	_name = NULL;
	_value = NULL;
	_length = 0;
	_position = 0;
	_displayName = NULL;

	_rubyName = Qnil;
	_rubyValue = Qnil;
	_rubyLength = Qnil;
	_rubyPosition = Qnil;
	_rubyDisplayName = Qnil;
	_rubyDisplayValue = Qnil;

	_packet = NULL;
}

Field::~Field(void) {
}
	
const guchar* Field::getValueForField(epan_dissect_t* edt, field_info *fi) {
	if (fi->length > tvb_length_remaining(fi->ds_tvb, fi->start)) {
		rb_raise(g_capfile_error_class, "field length invalid");
	}
	
	GSList *src_le;
	data_source *src;
	tvbuff_t *src_tvb;
	gint length, tvbuff_length;

	for (src_le = edt->pi.data_src; src_le != NULL; src_le = src_le->next) {
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
	
/*@ Methods implementing the Field Ruby object methods */
void Field::free(void* p) {
	Field* field = reinterpret_cast<Field*>(p);
	delete field;
}
	
void Field::mark(void* p) {
	//'mark' this object and any Ruby objects it references to avoid garbage collection
	Field* field = reinterpret_cast<Field*>(p);
	field->mark();
}

VALUE Field::alloc(VALUE klass) {
	//Allocate memory for the Field instance which will be tied to this Ruby object
	VALUE wrappedField;
	Field* field = new Field();

	wrappedField = Data_Wrap_Struct(klass, Field::mark, Field::free, field);

	return wrappedField;
}

VALUE Field::initialize(VALUE self, VALUE packetObject) {
    //Save off the parent packet
    rb_iv_set(self, "@packet", packetObject);

    return self;
}

VALUE Field::init_copy(VALUE copy, VALUE orig) {
	//Copy this object to a new one.  Open the cap file again
	Field* FieldCopy = NULL;
	Field* FieldOrig = NULL;

	if (copy == orig) {
		return copy;
	}
	
	if(TYPE(orig)!=T_DATA ||
		RDATA(orig)->dfree!=(RUBY_DATA_FUNC)Field::free) {
		rb_raise(rb_eTypeError, "Wrong argument type");
	}

	Data_Get_Struct(copy, Field, FieldCopy);
	Data_Get_Struct(orig, Field, FieldOrig);

	//Copy the Ruby property @packet, then copy the native Field objects too
	rb_iv_set(copy, "@packet", rb_iv_get(orig, "@packet"));

	*FieldCopy = *FieldOrig;

	return copy;
}
	
VALUE Field::name(VALUE self) {
	Field* field = NULL;
	Data_Get_Struct(self, Field, field);
	return field->getName();
}

VALUE Field::display_name(VALUE self) {
	Field* field = NULL;
	Data_Get_Struct(self, Field, field);
	return field->getDisplayName();
}

VALUE Field::value(VALUE self) {
	Field* field = NULL;
	Data_Get_Struct(self, Field, field);
	return field->getValue();
}

VALUE Field::display_value(VALUE self) {
	Field* field = NULL;
	Data_Get_Struct(self, Field, field);
	return field->getDisplayValue();
}

VALUE Field::length(VALUE self) {
	Field* field = NULL;
	Data_Get_Struct(self, Field, field);
	return field->getLength();
}

VALUE Field::position(VALUE self) {
	Field* field = NULL;
	Data_Get_Struct(self, Field, field);
	return field->getPosition();
}

void Field::mark() {
	//If any of our Ruby versions of properties are set, mark them
	if (_rubyName != Qnil) ::rb_gc_mark(_rubyName);
	if (_rubyValue != Qnil) ::rb_gc_mark(_rubyValue);
	if (_rubyLength != Qnil) ::rb_gc_mark(_rubyLength);
	if (_rubyPosition != Qnil) ::rb_gc_mark(_rubyPosition);
	if (_rubyDisplayName != Qnil) ::rb_gc_mark(_rubyDisplayName);
	if (_rubyDisplayValue != Qnil) ::rb_gc_mark(_rubyDisplayValue);
}

void Field::populateField() {
	//Extract the relevant bits from the field info

	field_info	*fi = PITEM_FINFO(_node);
	epan_dissect_t* edt = _packet->getEpanDissect();

	/* Text label. It's printed as a field with no name. */
	if (fi->hfinfo->id == hf_text_only) {
		_isProtocol = FALSE;

		/* Get the text */
		if (fi->rep) {
			_displayName = fi->rep->representation;
		}
		else {
			_displayName = "";
		}

		_length = fi->length;
		_position = fi->start;
		_value = getValueForField(edt, fi);
	}
	/* Uninterpreted data, i.e., the "Data" protocol, is
	 * printed as a field instead of a protocol. */
	else if (fi->hfinfo->id == proto_data) {
		_isProtocol = FALSE;
		_value = getValueForField(edt, fi);
	}
	/* Normal protocols and fields */
	else {
		if (fi->hfinfo->type == FT_PROTOCOL) {
			_isProtocol = TRUE;
		}
		else {
			_isProtocol = FALSE;
		}

		if (fi->rep) {
			_displayName = fi->rep->representation;
		}
		else {
			::proto_item_fill_label(fi, _displayNameBuffer);
			_displayName = _displayNameBuffer;
		}

		_length = fi->length;
		_position = fi->start;

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
			dfilter_string = ::proto_construct_match_selected_string(fi,
			    edt);
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

			/*
			 * XXX - should we omit "value" for any fields?
			 * What should we do for fields whose length is 0?
			 * They might come from a pseudo-header or from
			 * the capture header (e.g., time stamps), or
			 * they might be generated fields.
			 */
			if (fi->length > 0) {
				/*
				anelson - maybe we want to keep bitmask around?
				if (fi->hfinfo->bitmask!=0) {
					fprintf(stdout, "%X", fvalue_get_integer(&fi->value));
					fputs("\" unmaskedvalue=\"", stdout);
					write_field_hex_value(edt, fi);
				}
				else {
					write_field_hex_value(edt, fi);
				} */
				_value = getValueForField(edt, fi);
			}
		}
	}
}

VALUE Field::getName() {
	if (NIL_P(_rubyName)) {
		_rubyName = ::rb_str_new2(_name);
	}

	return _rubyName;
}

VALUE Field::getDisplayName() {
	if (NIL_P(_rubyDisplayName)) {
		_rubyDisplayName = ::rb_str_new2(_displayName);
	}

	return _rubyDisplayName;
}

VALUE Field::getValue() {
	if (NIL_P(_rubyValue)) {
		_rubyValue = ::rb_ary_new();
		for (guint idx = 0; idx < _length; idx++) {
			::rb_ary_push(_rubyValue, CHR2FIX(_value[idx]));
		}
	}

	return _rubyValue;
}

VALUE Field::getDisplayValue() {
	if (NIL_P(_rubyDisplayValue)) {
		_rubyDisplayValue = ::rb_str_new2(_displayValue.c_str());
	}

	return _rubyDisplayValue;
}

VALUE Field::getLength() {
	if (NIL_P(_rubyLength)) {
		_rubyLength = LONG2FIX(_length);
	}

	return _rubyLength;
}

VALUE Field::getPosition() {
	if (NIL_P(_rubyPosition)) {
		_rubyPosition = LONG2FIX(_position);
	}

	return _rubyPosition;
}


