#pragma once

#include "RubyAndShit.h"

/** The NativePointer class simply wraps a void* for use maintaining state */
class NativePointer
{
public:
	static VALUE createClass();

	/** Creates a new NativePointer object */
	static VALUE createNativePointer(void* pointer);
	static void* getPointer(VALUE nativePointer);

	template<typename _T>
	static _T* getPointer(VALUE pointerObject) {
		return reinterpret_cast<_T*>(getPointer(pointerObject));
	}

private:
	NativePointer();
	virtual ~NativePointer();

	static void free(void* p);
	static VALUE alloc(VALUE klass);
	static VALUE initialize(VALUE self);

	void* _ptr;
};
