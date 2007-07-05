#include "FieldQuery.h"

//Need some dissector constants
extern "C" {
#include "epan\dissectors\packet-frame.h"
#include "epan\dissectors\packet-data.h"
}

VALUE FieldQuery::createClass() {
    //Define the 'FieldQuery' class
	VALUE klass = rb_define_class_under(g_cap_dissector_module, "FieldQuery", rb_cObject);
	rb_define_alloc_func(klass, FieldQuery::alloc);

    //Define the 'initialize' method
    rb_define_method(klass,
                     "initialize", 
					 reinterpret_cast<VALUE(*)(ANYARGS)>(FieldQuery::initialize), 
					 1);

    rb_define_method(klass,
                     "name_is?", 
					 reinterpret_cast<VALUE(*)(ANYARGS)>(FieldQuery::name_is), 
					 1);

    rb_define_method(klass,
                     "name_is?", 
					 reinterpret_cast<VALUE(*)(ANYARGS)>(FieldQuery::name_is), 
					 1);

    rb_define_method(klass,
                     "display_value_is?", 
					 reinterpret_cast<VALUE(*)(ANYARGS)>(FieldQuery::display_value_is), 
					 1);

    rb_define_method(klass,
                     "display_name_is?", 
					 reinterpret_cast<VALUE(*)(ANYARGS)>(FieldQuery::display_name_is), 
					 1);

    rb_define_method(klass,
                     "sibling_name_is?", 
					 reinterpret_cast<VALUE(*)(ANYARGS)>(FieldQuery::sibling_name_is), 
					 1);

    rb_define_method(klass,
                     "sibling_matches?", 
					 reinterpret_cast<VALUE(*)(ANYARGS)>(FieldQuery::sibling_matches), 
					 1);

    rb_define_method(klass,
                     "has_display_name?", 
					 reinterpret_cast<VALUE(*)(ANYARGS)>(FieldQuery::has_display_name), 
					 0);

    rb_define_method(klass,
                     "has_value?", 
					 reinterpret_cast<VALUE(*)(ANYARGS)>(FieldQuery::has_value), 
					 0);

    rb_define_method(klass,
                     "has_display_value?", 
					 reinterpret_cast<VALUE(*)(ANYARGS)>(FieldQuery::has_display_value), 
					 0);

	return klass;
}
	
VALUE FieldQuery::createFieldQuery(VALUE packet) {
	//Create the FieldQuery ruby object first
	VALUE fieldQuery = rb_class_new_instance(0,
										 NULL,
										 g_field_query_class);

	//Get the wrapped FieldQuery object
	FieldQuery* nativeFieldQuery = NULL;
	Data_Get_Struct(fieldQuery, FieldQuery, nativeFieldQuery);

	//Get the wrapped Packet object in the Ruby Packet object
	Packet* nativePacket = NULL;
	Data_Get_Struct(packet, Packet, nativePacket);

	nativeFieldQuery->_self = fieldQuery;
	nativeFieldQuery->_packet = nativePacket;
	nativeFieldQuery->_rubyPacket = packet;

	return fieldQuery;
}

void FieldQuery::setFieldQueryCurrentNode(VALUE fieldQuery, ProtocolTreeNode* node) {
	FieldQuery* nativeFieldQuery = NULL;
	Data_Get_Struct(fieldQuery, FieldQuery, nativeFieldQuery);

	nativeFieldQuery->setCurrentNode(node);
}

bool FieldQuery::passFieldToProc(VALUE fieldQueryObject, VALUE proc) {
	//Ensure proc is in fact a proc
	proc = FieldQuery::ensureIsProc(proc);

	//Allocate a T_DATA object which will carry aroudn the RESCUE_STATE struct
	//used to keep state in the body and rescue methods where the work will happen
	VALUE state = ::rb_class_new_instance(INT2FIX(0),
		NULL,
		::rb_cObject);
	RESCUE_STRUCT rs = {0};

	rs.fieldQueryObject = fieldQueryObject;
	rs.proc = proc;

	Data_Wrap_Struct(::rb_obj_class(state), NULL, NULL, &rs);

	//Do the actual calling from the body function, and the exception handling in the rescue function
	::rb_rescue(reinterpret_cast<VALUE(*)(ANYARGS)>(FieldQuery::passFieldToProcBody),
		state,
		reinterpret_cast<VALUE(*)(ANYARGS)>(FieldQuery::passFieldToProcRescue),
		state);

	return rs.success;
}

void FieldQuery::setCurrentNode(ProtocolTreeNode* node) {
	_currentNode = node;
}

FieldQuery::FieldQuery() {
	::memset(&_currentNode, 0, sizeof(_currentNode));

	_packet = NULL;
	_self = Qnil;
	_rubyPacket = Qnil;
	_siblingsMatchesFieldQuery = Qnil;
}

FieldQuery::~FieldQuery(void) {
}
	
/*@ Methods implementing the FieldQuery Ruby object methods */
void FieldQuery::free(void* p) {
	FieldQuery* fieldQuery = reinterpret_cast<FieldQuery*>(p);
	delete fieldQuery;
}
	
void FieldQuery::mark(void* p) {
	//'mark' this object and any Ruby objects it references to avoid garbage collection
	FieldQuery* fieldQuery = reinterpret_cast<FieldQuery*>(p);
	fieldQuery->mark();
}

VALUE FieldQuery::alloc(VALUE klass) {
	//Allocate memory for the FieldQuery instance which will be tied to this Ruby object
	VALUE wrappedFieldQuery;
	FieldQuery* fieldQuery = new FieldQuery();

	wrappedFieldQuery = Data_Wrap_Struct(klass, FieldQuery::mark, FieldQuery::free, fieldQuery);

	return wrappedFieldQuery;
}

VALUE FieldQuery::initialize(VALUE self) {
    return self;
}

VALUE FieldQuery::init_copy(VALUE copy, VALUE orig) {
	//Copy this object to a new one.  Open the cap file again
	FieldQuery* FieldQueryCopy = NULL;
	FieldQuery* FieldQueryOrig = NULL;

	if (copy == orig) {
		return copy;
	}
	
	if(TYPE(orig)!=T_DATA ||
		RDATA(orig)->dfree!=(RUBY_DATA_FUNC)FieldQuery::free) {
		rb_raise(rb_eTypeError, "Wrong argument type");
	}

	Data_Get_Struct(copy, FieldQuery, FieldQueryCopy);
	Data_Get_Struct(orig, FieldQuery, FieldQueryOrig);

	*FieldQueryCopy = *FieldQueryOrig;

	return copy;
}
	
VALUE FieldQuery::name_is(VALUE self, VALUE match) {
	FieldQuery* fieldQuery = NULL;
	Data_Get_Struct(self, FieldQuery, fieldQuery);
	return fieldQuery->getNameIs(match);
}

VALUE FieldQuery::value_is(VALUE self, VALUE match) {
	FieldQuery* fieldQuery = NULL;
	Data_Get_Struct(self, FieldQuery, fieldQuery);
	return fieldQuery->getValueIs(match);
}

VALUE FieldQuery::display_value_is(VALUE self, VALUE match) {
	FieldQuery* fieldQuery = NULL;
	Data_Get_Struct(self, FieldQuery, fieldQuery);
	return fieldQuery->getDisplayValueIs(match);
}

VALUE FieldQuery::display_name_is(VALUE self, VALUE match) {
	FieldQuery* fieldQuery = NULL;
	Data_Get_Struct(self, FieldQuery, fieldQuery);
	return fieldQuery->getDisplayNameIs(match);
}

VALUE FieldQuery::sibling_name_is(VALUE self, VALUE match) {
	FieldQuery* fieldQuery = NULL;
	Data_Get_Struct(self, FieldQuery, fieldQuery);
	return fieldQuery->getSiblingNameIs(match);
}

VALUE FieldQuery::sibling_matches(VALUE self, VALUE query) {
	FieldQuery* fieldQuery = NULL;
	Data_Get_Struct(self, FieldQuery, fieldQuery);
	return fieldQuery->getSiblingMatches(query);
}

VALUE FieldQuery::has_display_name(VALUE self) {
	FieldQuery* fieldQuery = NULL;
	Data_Get_Struct(self, FieldQuery, fieldQuery);
	return fieldQuery->getHasDisplayName();
}

VALUE FieldQuery::has_value(VALUE self) {
	FieldQuery* fieldQuery = NULL;
	Data_Get_Struct(self, FieldQuery, fieldQuery);
	return fieldQuery->getHasValue();
}

VALUE FieldQuery::has_display_value(VALUE self) {
	FieldQuery* fieldQuery = NULL;
	Data_Get_Struct(self, FieldQuery, fieldQuery);
	return fieldQuery->getHasDisplayValue();
}

void FieldQuery::mark() {
	//If any of our Ruby versions of properties are set, mark them
	if (_rubyPacket != Qnil) ::rb_gc_mark(_rubyPacket);
	if (!NIL_P(_siblingsMatchesFieldQuery)) ::rb_gc_mark(_siblingsMatchesFieldQuery);
}

VALUE FieldQuery::getNameIs(VALUE match) {
	throwIfFalse(compareStrings(match, _currentNode->getName()));
	return Qtrue;
}

VALUE FieldQuery::getValueIs(VALUE match)  {
	throwIfFalse(compareByteArrays(match, _currentNode->getValue(), _currentNode->getFieldLength()));
	return Qtrue;
}

VALUE FieldQuery::getDisplayValueIs(VALUE match)  {
	throwIfFalse(compareStrings(match, _currentNode->getDisplayValue()));
	return Qtrue;
}

VALUE FieldQuery::getDisplayNameIs(VALUE match)  {
	throwIfFalse(compareStrings(match, _currentNode->getDisplayName()));
	return Qtrue;
}

VALUE FieldQuery::getSiblingNameIs(VALUE match) {
	Packet::NodeParentMap::iterator lbound;
	Packet::NodeParentMap::iterator ubound;

	_packet->getNodeSiblings(*_currentNode,
		lbound,
		ubound);

	for (Packet::NodeParentMap::iterator iter = lbound;
		iter != ubound;
		++iter) {
		//Don't include this node itself in the comparison
		if (iter->second != _currentNode) {
			if (compareStrings(match, iter->second->getName())) {
				return Qtrue;
			}
		}
	}

	throwIfFalse(false);
	return Qfalse;
}

VALUE FieldQuery::getSiblingMatches(VALUE query)  {
	//query needs to be a Proc object which we'll call once for each sibling
	VALUE proc = FieldQuery::ensureIsProc(query);

	//Create another FieldQuery object, if one doesn't already exist, 
	//to process this nested query
	if (NIL_P(_siblingsMatchesFieldQuery)) {
		_siblingsMatchesFieldQuery = FieldQuery::createFieldQuery(_rubyPacket);
	}
	
	Packet::NodeParentMap::iterator lbound;
	Packet::NodeParentMap::iterator ubound;

	_packet->getNodeSiblings(*_currentNode,
		lbound,
		ubound);

	for (Packet::NodeParentMap::iterator iter = lbound;
		iter != ubound;
		++iter) {
		//Don't include this node itself in the comparison
		if (iter->second == _currentNode) {
			continue;
		}

		//Pass this sibling FieldQuery object to the query proc
		if (passFieldToProc(_siblingsMatchesFieldQuery, proc)) {
			//Query proc matches this field; that means at least one sibling of this field
			//matches the query, so no further processing is needed
			return Qtrue;
		}
	}

	//No sibling matched the siblings query
	return Qfalse;
}

VALUE FieldQuery::getHasDisplayName() {
	return (isNotEmptyOrNull(_currentNode->getDisplayName()) ? Qtrue : Qfalse);
}

VALUE FieldQuery::getHasValue()  {
	return (_currentNode->getValue() != NULL ? Qtrue : Qfalse);
}

VALUE FieldQuery::getHasDisplayValue()  {
	return (isNotEmptyOrNull(_currentNode->getDisplayValue()) ? Qtrue : Qfalse);
}

bool FieldQuery::compareStrings(VALUE rubyString, const char* nativeString, bool caseSensitive /* = true */) {
	SafeStringValue(rubyString);

	if (rubyString == Qnil) {
		//Ruby string value is null, or is some object that can't be converted to a string
		return nativeString == NULL || *nativeString == '\0';
	} else if (nativeString == NULL) {
		//Native string is NULL, obviously Ruby string isn't, so it must be zero length to match
		return RSTRING(rubyString)->len == 0;
	}

	const char* compareString = RSTRING(rubyString)->ptr;
	size_t length = RSTRING(rubyString)->len;

	if (!caseSensitive) {
		return ::strnicmp(compareString, nativeString, length) == 0;
	} else {
		return ::strncmp(compareString, nativeString, length) == 0;
	}
}

bool FieldQuery::compareByteArrays(VALUE rubyAry, const guchar* nativeArray, guint nativeArrayLength) {
	VALUE ary = ::rb_check_array_type(rubyAry);

	guint length = RARRAY(ary)->len;
	if (length != nativeArrayLength) {
		return false;
	}

	for (guint idx = 0; idx < length; idx++) {
		unsigned char rubyByte = (unsigned char)NUM2INT(RARRAY(ary)->ptr[idx]);
		if (rubyByte != nativeArray[idx]) {
			return false;
		}
	}

	return true;
}

bool FieldQuery::isNotEmptyOrNull(const char* nativeString) {
	if (!nativeString) {return false;}
	if (nativeString[0] == '\0') {return false;}
	return true;
}

VALUE FieldQuery::ensureIsProc(VALUE in) {
	if (!::rb_obj_is_kind_of(in, ::rb_cProc)) {
		VALUE b = ::rb_check_convert_type(in, T_DATA, "Proc", "to_proc");
		if (!::rb_obj_is_kind_of(b, ::rb_cProc)) {
			::rb_raise(rb_eTypeError, "wrong argument type %s (expected Proc)",
				 ::rb_obj_classname(in));
		}
		in = b;
    }

	return in;
}

VALUE FieldQuery::passFieldToProcBody(VALUE state) {
	RESCUE_STRUCT* rs = NULL;
	Data_Get_Struct(state, RESCUE_STRUCT, rs);

	//Call the 'call' method on the proc object, passing in the field query object
	VALUE retval = ::rb_funcall(rs->proc, g_id_call, 1, rs->fieldQueryObject);

	//When execution gets this far, that means the query passed
	rs->success = true;
	return retval;
}

VALUE FieldQuery::passFieldToProcRescue(VALUE state, VALUE error_info) {
	RESCUE_STRUCT* rs = NULL;
	Data_Get_Struct(state, RESCUE_STRUCT, rs);

	//If this is the exception raised to indicate a query predicate didn't match, that just means
	//success goes to false and we're done.  If it's some other exception, rethrow it
	if (::rb_obj_is_kind_of(error_info, g_field_doesnt_match_error_class)) {
		rs->success = false;
	} else {
		::rb_exc_raise(error_info);
	}

	return Qnil;
}