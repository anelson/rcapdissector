#include "Blob.h"

VALUE Blob::createClass() {
    //Define the 'Blob' class
	VALUE klass = rb_define_class_under(g_cap_dissector_module, "Blob", rb_cObject);
	rb_define_alloc_func(klass, Blob::alloc);

    //Define the 'initialize' method
    rb_define_method(klass,
                     "initialize", 
					 reinterpret_cast<VALUE(*)(ANYARGS)>(Blob::initialize), 
					 1);

    //Define the 'packet' attribute reader
    rb_define_attr(klass,
                   "packet",
                   TRUE, 
                   FALSE);

    rb_define_method(klass,
                     "name", 
					 reinterpret_cast<VALUE(*)(ANYARGS)>(Blob::name), 
					 0);
    rb_define_method(klass,
                     "value", 
					 reinterpret_cast<VALUE(*)(ANYARGS)>(Blob::value), 
					 0);
    rb_define_method(klass,
                     "length", 
					 reinterpret_cast<VALUE(*)(ANYARGS)>(Blob::length), 
					 0);

	return klass;
}

VALUE Blob::createBlob(VALUE packet, data_source* ds) {
	//Create the Blob ruby object first
	VALUE argv[] = {
		packet
	};

	//Create a Blob object for this packet
	VALUE blob = rb_class_new_instance(sizeof(argv)/sizeof(argv[0]),
										 argv,
										 g_blob_class);

	//Get the wrapped Blob object
	Blob* nativeBlob = NULL;
	Data_Get_Struct(blob, Blob, nativeBlob);

	nativeBlob->_self = blob;
	nativeBlob->_ds = ds;

	return blob;
}

Blob::Blob(void) {
	_rubyName = Qnil;
	_rubyValue = Qnil;
	_rubyLength = Qnil;

	_ds = NULL;
}

Blob::~Blob(void) {
}

void Blob::free(void* p) {
	Blob* blob = reinterpret_cast<Blob*>(p);
	delete blob;
}

void Blob::mark(void* p)  {
	//'mark' this object and any Ruby objects it references to avoid garbage collection
	Blob* blob = reinterpret_cast<Blob*>(p);
	blob->mark();
}

VALUE Blob::alloc(VALUE klass) {
	//Allocate memory for the Blob instance which will be tied to this Ruby object
	VALUE wrappedBlob;
	Blob* blob = new Blob();

	wrappedBlob = Data_Wrap_Struct(klass, Blob::mark, Blob::free, blob);

	return wrappedBlob;
}


VALUE Blob::initialize(VALUE self, VALUE packetObject) {
    //Save off the parent packet
    rb_iv_set(self, "@packet", packetObject);

    return self;
}

VALUE Blob::init_copy(VALUE copy, VALUE orig) {
	//Copy this object to a new one.  Open the cap file again
	Blob* BlobCopy = NULL;
	Blob* BlobOrig = NULL;

	if (copy == orig) {
		return copy;
	}
	
	if(TYPE(orig)!=T_DATA ||
		RDATA(orig)->dfree!=(RUBY_DATA_FUNC)Blob::free) {
		rb_raise(rb_eTypeError, "Wrong argument type");
	}

	Data_Get_Struct(copy, Blob, BlobCopy);
	Data_Get_Struct(orig, Blob, BlobOrig);

	//Copy the Ruby property @packet, then copy the native Blob objects too
	rb_iv_set(copy, "@packet", rb_iv_get(orig, "@packet"));

	*BlobCopy = *BlobOrig;

	return copy;
}

VALUE Blob::name(VALUE self) {
	Blob* blob = NULL;
	Data_Get_Struct(self, Blob, blob);
	return blob->getName();
}

VALUE Blob::value(VALUE self) {
	Blob* blob = NULL;
	Data_Get_Struct(self, Blob, blob);
	return blob->getValue();
}

VALUE Blob::length(VALUE self) {
	Blob* blob = NULL;
	Data_Get_Struct(self, Blob, blob);
	return blob->getLength();
}

void Blob::mark() {
	//If any of our Ruby versions of properties are set, mark them
	if (_rubyName != Qnil) ::rb_gc_mark(_rubyName);
	if (_rubyValue != Qnil) ::rb_gc_mark(_rubyValue);
	if (_rubyLength != Qnil) ::rb_gc_mark(_rubyLength);
}


VALUE Blob::getName() {
	if (NIL_P(_rubyName)) {
		_rubyName = rubyStringFromCString(_ds->name);
	}

	return _rubyName;
}

VALUE Blob::getValue() {
	if (NIL_P(_rubyValue)) {
		//NB: If tvb represents a large block of data broken up into multiple child buffers,
		//calling tvb_get_ptr forces a new buffer to be allocated to contain all the data in one
		//contiguous range.  This can be a huge hit if the buffer is large.  Should add a chunked read API
		//that takes into account the actual TVB boundaries when doing the chunking

		//ANOTHER OPTIMIZATION IDEA: These blobs are most likely going to be pushed back down to a C API for storage into 
		//a database (sqlite, etc).  That's one copy to create the Ruby Array, and another to put it back into a native buffer
		//Is there some way we could wrap a native pointer in a light Ruby object such that it can be put back into a native pointer
		//at the API end?
		//
		//Worth looking into if the blob performance starts to suck wind
		const guint8* value = ::tvb_get_ptr(_ds->tvb, 0, ::tvb_length(_ds->tvb));

		if (value) {
			_rubyValue = ::rb_str_new(reinterpret_cast<const char*>(value), ::tvb_length(_ds->tvb));
		}
	}

	return _rubyValue;
}

VALUE Blob::getLength() {
	if (NIL_P(_rubyLength)) {
		_rubyLength = LONG2FIX(::tvb_length(_ds->tvb));
	}

	return _rubyLength;
}

