#pragma once

#include "RubyAndShit.h"

#include "NativePacket.h"
#include "ProtocolTreeNode.h"


/** The FieldQuery class represents a single field within a packet when a query proc is being evaluated.
The FieldQuery object is more lightweight than a Field object, and is reused for all fields within a packet,
thus it's the prefered way for Ruby code to select packet fields in which it is interested.  */
class FieldQuery
{
public:
	static VALUE createClass();

	/** Creates a new FieldQuery object */
	static VALUE createFieldQuery(VALUE packet);

	/** Extracts the native FieldQuery object from a Ruby object and calls setCurrentNode passing in 'node' */
	static void setFieldQueryCurrentNode(VALUE fieldQuery, ProtocolTreeNode* node);

	/** Invokes the given Proc object passing the given FieldQuery object to the Proc.
	If the Proc throws an FieldDoesNotMatchQueryError, the error is caught and this method returns
	false.  If proc runs without any exceptions, returns true.  If proc raises some other exception, that exception
	is re-raised and passed up the stack frame */
	static bool passFieldToProc(VALUE fieldQueryObject, VALUE proc);

	/** Associates this object with the given node; all calls to the predicate methods will
	evaluate the predicates in terms of this node (or 'Field' to Ruby callers) */
	void setCurrentNode(ProtocolTreeNode* node);

private:
	FieldQuery();
	virtual ~FieldQuery(void);

	const FieldQuery& operator=(const FieldQuery&) {
		//TODO: Implement
		return *this;
	}

	/*@ Methods implementing the FieldQuery Ruby object methods */
	static void free(void* p);
	static void mark(void* p);
	static VALUE alloc(VALUE klass);
	static VALUE initialize(VALUE self);
	static VALUE init_copy(VALUE copy, VALUE orig);

	static VALUE get_field(VALUE self);

	static VALUE name_is(VALUE self, VALUE match);
	static VALUE value_is(VALUE self, VALUE match);
	static VALUE display_value_is(VALUE self, VALUE match);
	static VALUE display_name_is(VALUE self, VALUE match);
	static VALUE sibling_name_is(VALUE self, VALUE match);
	static VALUE sibling_matches(VALUE self, VALUE query);

	static VALUE has_display_name(VALUE self);
	static VALUE has_value(VALUE self);
	static VALUE has_display_value(VALUE self);


	/*@ Instance methods that actually perform the FieldQuery-specific work */
	void mark();
	VALUE getField();
	VALUE getNameIs(VALUE match);
	VALUE getValueIs(VALUE match);
	VALUE getDisplayValueIs(VALUE match);
	VALUE getDisplayNameIs(VALUE match);
	VALUE getSiblingNameIs(VALUE match);
	VALUE getSiblingMatches(VALUE query);

	VALUE getHasDisplayName();
	VALUE getHasValue();
	VALUE getHasDisplayValue();

	static bool compareStrings(VALUE rubyString, const char* nativeString, bool caseSensitive = true);
	static bool compareByteArrays(VALUE rubyAry, const guchar* nativeArray, guint nativeArrayLength);
	static bool isNotEmptyOrNull(const char* nativeString);
	static void throwIfFalse(bool value) {
		//Throw the FieldDoesNotMatchQueryError exception if value is false, indicating something
		//didn't match
		if (!value) {
			::rb_raise(g_field_doesnt_match_error_class, "");
		}
	}

	/** Ensures 'in' is of type Proc, attempting coercion if necessary.  Throws on error; returns Proc object on success */
	static VALUE ensureIsProc(VALUE in);

	VALUE _self;
	VALUE _rubyPacket;
	Packet* _packet;
	ProtocolTreeNode* _currentNode;

	/** Cached instance of FieldQuery object used to process sibling_matches? query predicates without
	creating a new object each time */
	VALUE _siblingsMatchesFieldQuery;
};
