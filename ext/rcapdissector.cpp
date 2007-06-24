#include <winsock2.h>
#include <windows.h>

#include "rcapdissector.h"

#include "CapFile.h"
#include "NativePacket.h"
#include "Field.h"

VALUE g_packet_class;
VALUE g_protocol_class;
VALUE g_field_class;
VALUE g_capfile_error_class;

VALUE g_add_element_func;
VALUE g_at_func;

VALUE g_cap_dissector_module;
VALUE g_cap_file_class;

extern "C" __declspec(dllexport) void Init_capdissector() {
    //Find the native-ruby companion classes that we need
    rb_require("capdissector");

	CapFile::initPacketCapture();

    //g_packet_class = rb_path2class("CapDissector::Packet");
    //g_protocol_class = rb_path2class("CapDissector::Protocol");
    //g_field_class = rb_path2class("CapDissector::Field");
    g_capfile_error_class = rb_path2class("CapDissector::CapFileError");
	//g_add_element_func = rb_intern("add_element");
	//g_at_func = rb_intern("at");

    //Define the 'CapDissector' module
    g_cap_dissector_module = rb_define_module("CapDissector");

	//Define the CapFile class
	g_cap_file_class = CapFile::createClass();
	g_packet_class = Packet::createClass();
	g_field_class = Field::createClass();
}

