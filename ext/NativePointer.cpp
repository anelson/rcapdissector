#include "NativePointer.h"

#include "rcapdissector.h"


VALUE NativePointer::createClass() {
	VALUE klass = ::rb_define_class_under(g_cap_dissector_module, "NativePointer", rb_cObject);
	rb_define_alloc_func(klass, NativePointer::alloc);

    //Define the 'initialize' method
    rb_define_method(klass,
                     "initialize", 
					 reinterpret_cast<VALUE(*)(ANYARGS)>(NativePointer::initialize), 
					 0);

	return klass;
}

VALUE NativePointer::createNativePointer(void* pointer) {
	//Create the NativePointer ruby object first
	VALUE ptr = rb_class_new_instance(0,
										 NULL,
										 g_native_pointer_class);

	NativePointer* nativePtr = NULL;
	Data_Get_Struct(ptr, NativePointer, nativePtr);
	nativePtr->_ptr = pointer;

	return ptr;
}
	
void* NativePointer::getPointer(VALUE nativePointerObject) {
	NativePointer* nativePointer = NULL;
	Data_Get_Struct(nativePointerObject, NativePointer, nativePointer);
	return nativePointer->_ptr;
}

NativePointer::NativePointer() {
	_ptr = NULL;
}

NativePointer::~NativePointer() {
}

void NativePointer::free(void* p) {
	NativePointer* ptr = reinterpret_cast<NativePointer*>(p);
	delete ptr;
}

VALUE NativePointer::alloc(VALUE klass) {
	NativePointer* ptr = new NativePointer();
	return Data_Wrap_Struct(klass, NULL, NULL, ptr);
}

VALUE NativePointer::initialize(VALUE self) {
	return self;
}


