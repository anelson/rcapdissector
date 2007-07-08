#include "Field.h"

#include <string>
#include <sstream>

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
                     "to_s", 
					 reinterpret_cast<VALUE(*)(ANYARGS)>(Field::to_s), 
					 0);

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
	
VALUE Field::createField(VALUE packet, ProtocolTreeNode* node) {
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
	nativeField->_node = node;

	return field;
}

Field::Field() {
	_node = NULL;

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

VALUE Field::rubyStringFromCString(const gchar* str) {
	if (str) {
		return ::rb_str_new2(str);
	} else {
		return Qnil;
	}
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

VALUE Field::to_s(VALUE self) {
	Field* field = NULL;
	Data_Get_Struct(self, Field, field);
	return field->toString();
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
	
VALUE Field::toString() {
	std::stringstream str;

	//Build a string representation of this field
	if (::strlen(_node->getName()) > 0) {
		str << _node->getName();
	} else {
		str << "[Field ordinal " << _node->getOrdinal() << "]";
	}

	str << "; ";

	if (_node->getDisplayName() != NULL &&
		::strlen(_node->getDisplayName()) > 0) {
		str << "(" << _node->getDisplayName() << "); ";
	}

	if (_node->getDisplayValue() != NULL &&
		::strlen(_node->getDisplayValue()) > 0) { 
		str << "Display Value: [" << _node->getDisplayValue() << "]; ";
	}

	if (_node->getValue()) {
		str << "Value: [";
		guint idx = 0;
		while (idx < _node->getFieldLength() && idx < 10) {
			str << std::hex << static_cast<int>(_node->getValue()[idx]) << " ";
			idx++;
		}

		str << "]";
	}

	std::string string = str.str();

	return ::rb_str_new(string.c_str(),
		static_cast<long>(string.length()));
}

VALUE Field::getName() {
	if (NIL_P(_rubyName)) {
		_rubyName = rubyStringFromCString(_node->getName());
	}

	return _rubyName;
}

VALUE Field::getDisplayName() {
	if (NIL_P(_rubyDisplayName)) {
		_rubyDisplayName = rubyStringFromCString(_node->getDisplayName());
	}

	return _rubyDisplayName;
}

VALUE Field::getValue() {
	if (NIL_P(_rubyValue)) {
		const guchar* value = _node->getValue();

		_rubyValue = ::rb_ary_new();
		for (guint idx = 0; idx < _node->getFieldLength(); idx++) {
			::rb_ary_push(_rubyValue, CHR2FIX(value[idx]));
		}
	}

	return _rubyValue;
}

VALUE Field::getDisplayValue() {
	if (NIL_P(_rubyDisplayValue)) {
		_rubyDisplayValue = rubyStringFromCString(_node->getDisplayValue());
	}

	return _rubyDisplayValue;
}

VALUE Field::getLength() {
	if (NIL_P(_rubyLength)) {
		_rubyLength = LONG2FIX(_node->getFieldLength());
	}

	return _rubyLength;
}

VALUE Field::getPosition() {
	if (NIL_P(_rubyPosition)) {
		_rubyPosition = LONG2FIX(_node->getPosition());
	}

	return _rubyPosition;
}


