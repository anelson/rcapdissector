#include "NativePacket.h"
#include "Field.h"

//Need some dissector constants
extern "C" {
#include "epan\dissectors\packet-frame.h"
#include "epan\dissectors\packet-data.h"
}

VALUE Packet::createClass() {
    //Define the 'Packet' class
	VALUE klass = rb_define_class_under(g_cap_dissector_module, "Packet", rb_cObject);
	rb_define_alloc_func(klass, Packet::alloc);

    //Define the 'initialize' method
    rb_define_method(klass,
                     "initialize", 
					 reinterpret_cast<VALUE(*)(ANYARGS)>(Packet::initialize), 
					 1);

    //Define the 'capfile' attribute reader
    rb_define_attr(klass,
                   "capfile",
                   TRUE, 
                   FALSE);

    rb_define_method(klass,
                     "field_exists?", 
					 reinterpret_cast<VALUE(*)(ANYARGS)>(Packet::field_exists), 
					 1);

    rb_define_method(klass,
                     "descendant_field_exists?", 
					 reinterpret_cast<VALUE(*)(ANYARGS)>(Packet::descendant_field_exists), 
					 2);

    rb_define_method(klass,
                     "find_first_field", 
					 reinterpret_cast<VALUE(*)(ANYARGS)>(Packet::find_first_field), 
					 1);

    rb_define_method(klass,
                     "each_field", 
					 reinterpret_cast<VALUE(*)(ANYARGS)>(Packet::each_field), 
					 -1);

    rb_define_method(klass,
                     "find_first_descendant_field", 
					 reinterpret_cast<VALUE(*)(ANYARGS)>(Packet::find_first_descendant_field), 
					 2);

    rb_define_method(klass,
                     "each_descendant_field", 
					 reinterpret_cast<VALUE(*)(ANYARGS)>(Packet::each_descendant_field), 
					 -1);

	return klass;
}

#pragma warning(push)
#pragma warning(disable : 4702) //unreachable code

gboolean Packet::getNextPacket(VALUE capFileObject, capture_file& cf, VALUE& packet) {
    int err = 0;
    gchar* err_info = NULL;
    gint64 data_offset = 0;
    gchar err_msg[2048];

	packet = Qnil;

	do {
		if (!wtap_read(cf.wth, &err, &err_info, &data_offset)) {
			if (err == 0) {
				//Nothing wrong, just at the end of the file
				return FALSE;
			} else {
				goto error;
			}
		} else if (err != 0) {
			//Something amiss
			goto error;
		}
		
		//processPacket will return Qnil if the packet doesn't match the filter rule
		//associated with cf
		packet = processPacket(capFileObject, cf, data_offset);		
	} while (NIL_P(packet));

    return TRUE;

    error:
    /* Throw exception noting that the read failed somewhere along the line. */

    switch (err) {
    
    case WTAP_ERR_UNSUPPORTED_ENCAP:
        g_snprintf(err_msg, sizeof(err_msg),
                   "\"%s\" has a packet with a network type that Wireshark doesn't support.\n(%s)",
                   cf.filename, err_info);
        break;

    case WTAP_ERR_CANT_READ:
        g_snprintf(err_msg, sizeof(err_msg),
                   "An attempt to read from \"%s\" failed for some unknown reason.",
                   cf.filename);
        break;

    case WTAP_ERR_SHORT_READ:
        g_snprintf(err_msg, sizeof(err_msg),
                   "\"%s\" appears to have been cut short in the middle of a packet.",
                   cf.filename);
        break;

    case WTAP_ERR_BAD_RECORD:
        g_snprintf(err_msg, sizeof(err_msg),
                   "\"%s\" appears to be damaged or corrupt.\n(%s)",
                   cf.filename, err_info);
        break;

    default:
        g_snprintf(err_msg, sizeof(err_msg),
                   "An error occurred while reading \"%s\": %s.",
                   cf.filename, wtap_strerror(err));
        break;
    }

    rb_raise(g_capfile_error_class, err_msg);

    //Execution never makes it this far
	return FALSE;
}
#pragma warning(pop)

Packet::Packet() {
	_edt = NULL;
	_wth = NULL;
	_cf = NULL;
}

Packet::~Packet(void) {
	for (NodeNameMap::iterator iter = _nodesByName.begin();
		iter != _nodesByName.end();
		++iter) {
		if (iter->second) {
			delete iter->second;
		}
	}
	_nodesByName.clear();
	_nodesByParent.clear();

	if (_edt) {
		epan_dissect_free(_edt);
		_edt = NULL;
	}
	
	clearFdata(&_frameData);
}
	
VALUE Packet::processPacket(VALUE capFileObject, capture_file& cf, gint64 offset) {
	VALUE packet = Qnil;
	
	struct wtap_pkthdr *whdr = wtap_phdr(cf.wth);
	union wtap_pseudo_header *pseudo_header = wtap_pseudoheader(cf.wth);
	const guchar* pd = wtap_buf_ptr(cf.wth);

    frame_data fdata;
    epan_dissect_t *edt;
    gboolean passed;

    /* Count this packet. */
    cf.count++;

    /* If we're going to print packet information, or we're going to
       run a read filter, or we're going to process taps, set up to
       do a dissection and do so. */
    fillInFdata(&fdata, cf, whdr, offset);

    passed = TRUE;
    edt = epan_dissect_new(TRUE, TRUE);

    /* If we're running a read filter, prime the epan_dissect_t with that
       filter. */
    if (cf.rfcode)
        epan_dissect_prime_dfilter(edt, cf.rfcode);

    tap_queue_init(edt);

    /* We only need the columns if we're printing packet info but we're
       *not* verbose; in verbose mode, we print the protocol tree, not
       the protocol summary. */
    epan_dissect_run(edt, pseudo_header, pd, &fdata,
                     NULL);

    tap_push_tapped_queue(edt);

    /* Run the read filter if we have one. */
    if (cf.rfcode)
        passed = dfilter_apply_edt(cf.rfcode, edt);
    else
        passed = TRUE;

    if (passed) {
        /* Passes the filter critera.  Create a Ruby Packet object and build it. */
#ifndef SKIP_OBJECT_CREATION
		VALUE argv[] = {
			capFileObject
		};

		//Create a Packet object for this packet
		packet = rb_class_new_instance(_countof(argv),
											 argv,
											 g_packet_class);

		//Get the wrapped Packet object
		Packet* nativePacket = NULL;
		Data_Get_Struct(packet, Packet, nativePacket);

		nativePacket->_frameData = fdata;
		nativePacket->_edt = edt;
		nativePacket->_wth = cf.wth;
		nativePacket->_cf = &cf;

		nativePacket->buildPacket();
#else
		capFileObject;
		Packet* nativePacket = new Packet();
		nativePacket->_edt = edt;
		nativePacket->_wth = cf.wth;
		nativePacket->_cf = &cf;

		nativePacket->buildPacket();
		delete nativePacket;
#endif

	} else {
		//Didn't pass filter, so free the packet info
		epan_dissect_free(edt);
		clearFdata(&fdata);
	}

	return packet;
}


void Packet::fillInFdata(frame_data *fdata, capture_file& cf,
              const struct wtap_pkthdr *phdr, gint64 offset)
{
  static guint32 cum_bytes = 0;

  fdata->next = NULL;
  fdata->prev = NULL;
  fdata->pfd = NULL;
  fdata->num = cf.count;
  fdata->pkt_len = phdr->len;
  cum_bytes += phdr->len;
  fdata->cum_bytes  = cum_bytes;
  fdata->cap_len = phdr->caplen;
  fdata->file_off = offset;
  fdata->lnk_t = phdr->pkt_encap;
  fdata->abs_ts = *((nstime_t *) &phdr->ts);
  fdata->flags.passed_dfilter = 0;
  fdata->flags.encoding = CHAR_ASCII;
  fdata->flags.visited = 0;
  fdata->flags.marked = 0;
  fdata->flags.ref_time = 0;
  fdata->color_filter = NULL;

  /* Don't bother with computing a relative time, so set the rel time to the abs time */
  fdata->rel_ts = fdata->abs_ts;
  fdata->del_ts = fdata->abs_ts;
}

void Packet::clearFdata(frame_data *fdata)
{
  if (fdata->pfd)
    g_slist_free(fdata->pfd);
}

/*@ Methods implementing the Packet Ruby object methods */
void Packet::free(void* p) {
	Packet* packet = reinterpret_cast<Packet*>(p);
	delete packet;
}
	
void Packet::mark(void* p) {
	//'mark' this object and any Ruby objects it references to avoid garbage collection
	Packet* packet = reinterpret_cast<Packet*>(p);

	packet->mark();
}

VALUE Packet::alloc(VALUE klass) {
	//Allocate memory for the Packet instance which will be tied to this Ruby object
	VALUE wrappedpacket;
	Packet* packet = new Packet();

	wrappedpacket = Data_Wrap_Struct(klass, Packet::mark, Packet::free, packet);

	return wrappedpacket;
}

VALUE Packet::initialize(VALUE self, VALUE capFileObject) {
    //Save off the Packet name
    rb_iv_set(self, "@capfile", capFileObject);

	Packet* packet = NULL;
	Data_Get_Struct(self, Packet, packet);
	packet->_self = self;

    return self;
}

VALUE Packet::init_copy(VALUE copy, VALUE orig) {
	//Copy this object to a new one.  Open the cap file again
	Packet* packetCopy = NULL;
	Packet* packetOrig = NULL;

	if (copy == orig) {
		return copy;
	}
	
	if(TYPE(orig)!=T_DATA ||
		RDATA(orig)->dfree!=(RUBY_DATA_FUNC)Packet::free) {
		rb_raise(rb_eTypeError, "Wrong argument type");
	}

	Data_Get_Struct(copy, Packet, packetCopy);
	Data_Get_Struct(orig, Packet, packetOrig);

	//Copy the Ruby property @capfile, then copy the native Packet objects too
	VALUE capFileObject = rb_iv_get(orig, "@capfile");
	rb_iv_set(copy, "@capfile", capFileObject);

	*packetCopy = *packetOrig;

	return copy;
}
	
VALUE Packet::field_exists(VALUE self, VALUE fieldName) {
	Packet* packet = NULL;
	Data_Get_Struct(self, Packet, packet);
	return packet->fieldExists(fieldName);
}
	
VALUE Packet::descendant_field_exists(VALUE self, VALUE parentField, VALUE fieldName) {
	Packet* packet = NULL;
	Data_Get_Struct(self, Packet, packet);
	return packet->descendantFieldExists(parentField, fieldName);
}

VALUE Packet::find_first_field(VALUE self, VALUE fieldName) {
	Packet* packet = NULL;
	Data_Get_Struct(self, Packet, packet);
	return packet->findFirstField(fieldName);
}

VALUE Packet::each_field(int argc, VALUE* argv, VALUE self) {
	Packet* packet = NULL;
	Data_Get_Struct(self, Packet, packet);
	return packet->eachField(argc, argv);
}

VALUE Packet::find_first_descendant_field(VALUE self, VALUE parentField, VALUE fieldName) {
	Packet* packet = NULL;
	Data_Get_Struct(self, Packet, packet);
	return packet->findFirstDescendantField(parentField, fieldName);
}

VALUE Packet::each_descendant_field(int argc, VALUE* argv, VALUE self) {
	Packet* packet = NULL;
	Data_Get_Struct(self, Packet, packet);
	return packet->eachDescendantField(argc, argv);
}

void Packet::buildPacket() {
	//Add each of this packet's nodes to our node map
	::proto_tree_children_foreach(_edt->tree, 
		addNodeThunk,
	    this);
}

void Packet::addNodeThunk(proto_node *node, gpointer data) {
	Packet* packet = reinterpret_cast<Packet*>(data);

	packet->addNode(node);
}

void Packet::addNode(proto_node* node) {
	//Add this node to the node map in two ways: by its header name,
	//and by its parent's pointer value.  This allows access to fields by name
	//and by parent field
	field_info	*fi = PITEM_FINFO(node);
	const gchar* name = NULL;
	
	if (fi->hfinfo->id == hf_text_only) {
		//Text only node; no name
		name = "";
	} else if (fi->hfinfo->id == proto_data) {
		//Data node.  we'll call it 'data'
		name = "data";
	} else {
		//A normal protocol or field node
		name = fi->hfinfo->abbrev;
	}

	NODE_STRUCT* nodeStruct = new NODE_STRUCT;
	nodeStruct->name = name;
	nodeStruct->node = node;
	nodeStruct->fieldObject = Qnil;

	_nodesByName.insert(NodeNameMap::value_type(name, nodeStruct));
	_nodesByParent.insert(NodeParentMap::value_type((guint64)node->parent, nodeStruct));
}
	
VALUE Packet::getRubyFieldObjectForField(NODE_STRUCT& node) {
	//Has a Ruby Field object been created for this field yet?  If not, do that now	
	if (NIL_P(node.fieldObject)) {
		node.fieldObject = Field::createField(_self,
			node.name,
			node.node);
	}

	return node.fieldObject;
}

void Packet::mark() {
	//Mark all the Ruby Field objects we know about
	for (NodeNameMap::const_iterator iter = _nodesByName.begin();
		iter != _nodesByName.end();
		++iter) {
		if (iter->second->fieldObject != Qnil) {
			::rb_gc_mark(iter->second->fieldObject);
		}
	}
}

VALUE Packet::fieldExists(VALUE fieldName) {
	const gchar* name = RSTRING(::StringValue(fieldName))->ptr;

	if (_nodesByName.find(name) == _nodesByName.end()) {
		return Qfalse;
	} else {
		return Qtrue;
	}
}

VALUE Packet::descendantFieldExists(VALUE fieldName, VALUE parentField) {
	//Look for the given field name in the descendants of this field
	if (NIL_P(parentField)) return Qfalse;

	const gchar* name = RSTRING(::StringValue(fieldName))->ptr;

	Field* field = NULL;
	Data_Get_Struct(parentField, Field, field);
	NodeParentMap::const_iterator lbound = _nodesByParent.lower_bound((guint64)field->getProtoNode());
	NodeParentMap::const_iterator ubound = _nodesByParent.upper_bound((guint64)field->getProtoNode());
	for (NodeParentMap::const_iterator iter = lbound;
		iter != ubound;
		++iter) {
		if (::strcmp(name, iter->second->name) == 0) {
			//Found it
			return Qtrue;
		}
	}

	return Qfalse;
}

VALUE Packet::findFirstField(VALUE fieldName) {
	const gchar* name = RSTRING(::StringValue(fieldName))->ptr;
	if (!name) return Qnil;

	NodeNameMap::iterator iter = _nodesByName.find(name);
	if (iter == _nodesByName.end()) {
		return Qnil;
	}

	return getRubyFieldObjectForField(*iter->second);
}

VALUE Packet::eachField(int argc, VALUE* argv) {
	rb_need_block();

	//each_field expects zero or one arguments
	//0 args will yield once for each field in the packet
	if (argc < 0 || argc > 1) {
		::rb_raise(::rb_eArgError, "each_field expects 0 or 1 args");
	}

	const gchar* fieldName = NULL;
	if (argc == 1 && !NIL_P(argv[0])) {
		VALUE fn = ::StringValue(argv[0]);
		fieldName = RSTRING(fn)->ptr;
	}

	NodeNameMap::iterator lbound, ubound;

	if (fieldName) {
		//Limit the range to elements matching the range
		lbound = _nodesByName.lower_bound(fieldName);
		ubound = _nodesByName.upper_bound(fieldName);
	} else {
		//Include all fields
		lbound = _nodesByName.begin();
		ubound = _nodesByName.end();
	}

	for (NodeNameMap::iterator iter = lbound;
		iter != ubound;
		++iter) {
		::rb_yield(getRubyFieldObjectForField(*iter->second));
	}

	return _self;
}

VALUE Packet::findFirstDescendantField(VALUE parentField, VALUE fieldName) {
	//Look for the given field name in the descendants of this field
	if (NIL_P(parentField)) return Qfalse;

	const gchar* name = RSTRING(::StringValue(fieldName))->ptr;
	if (!name) {
		return Qnil;
	}

	Field* field = NULL;
	Data_Get_Struct(parentField, Field, field);
	NodeParentMap::iterator lbound = _nodesByParent.lower_bound((guint64)field->getProtoNode());
	NodeParentMap::iterator ubound = _nodesByParent.upper_bound((guint64)field->getProtoNode());
	for (NodeParentMap::iterator iter = lbound;
		iter != ubound;
		++iter) {
		if (::strcmp(name, iter->second->name) == 0) {
			//Found it
			return getRubyFieldObjectForField(*iter->second);
		}
	}

	return Qnil;
}

VALUE Packet::eachDescendantField(int argc, VALUE* argv) {
	rb_need_block();

	//each_field expects 1 or two args
	//first is always the parent field whose descendants we're looking at
	//second, if present, is the name of the field to find.  If missing, includes
	//all fields
	if (argc < 1 || argc > 2) {
		::rb_raise(::rb_eArgError, "each_descendant_field expects 1 or 2 args");
	}

	VALUE parentField = argv[0];
	if (::rb_obj_class(parentField) != g_field_class) {
		::rb_raise(::rb_eArgError,
			"The first argument must be the parent field of type Field");
	}
	Field* parentFieldPtr = NULL;
	Data_Get_Struct(parentField, Field, parentFieldPtr);

	const gchar* fieldName = NULL;
	if (argc == 2 && !NIL_P(argv[1])) {
		VALUE fn = ::StringValue(argv[1]);
		fieldName = RSTRING(fn)->ptr;
	}

	NodeParentMap::iterator lbound, ubound;
	lbound = _nodesByParent.lower_bound((guint64)parentFieldPtr->getProtoNode());
	ubound = _nodesByParent.upper_bound((guint64)parentFieldPtr->getProtoNode());

	for (NodeParentMap::iterator iter = lbound;
		iter != ubound;
		++iter) {
		//If the fieldName is non-null, filter on that
		if (!fieldName ||
			(::strcmp(fieldName, iter->second->name) == 0)) {
			//Found a matching field
			::rb_yield(getRubyFieldObjectForField(*iter->second));
		}
	}

	return _self;
}
