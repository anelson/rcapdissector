#include "NativePacket.h"
#include "Field.h"
#include "FieldQuery.h"

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

	
    rb_define_method(klass,
                     "field_matches?", 
					 reinterpret_cast<VALUE(*)(ANYARGS)>(Packet::field_matches), 
					 1);

    rb_define_method(klass,
                     "descendant_field_matches?", 
					 reinterpret_cast<VALUE(*)(ANYARGS)>(Packet::descendant_field_matches), 
					 2);

    rb_define_method(klass,
                     "find_first_field_match", 
					 reinterpret_cast<VALUE(*)(ANYARGS)>(Packet::find_first_field_match), 
					 1);

    rb_define_method(klass,
                     "each_field_match", 
					 reinterpret_cast<VALUE(*)(ANYARGS)>(Packet::each_field_match), 
					 1);

    rb_define_method(klass,
                     "find_first_descendant_field_match", 
					 reinterpret_cast<VALUE(*)(ANYARGS)>(Packet::find_first_descendant_field_match), 
					 2);

    rb_define_method(klass,
                     "each_descendant_field_match", 
					 reinterpret_cast<VALUE(*)(ANYARGS)>(Packet::each_descendant_field_match), 
					 2);

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

void Packet::getNodeSiblings(ProtocolTreeNode& node, NodeParentMap::iterator& lbound, NodeParentMap::iterator& ubound) {
	guint64 parentPtr = 0;
	if (node.getParentNode() != NULL) {
		parentPtr = (guint64)node.getParentNode()->getProtoNode();
	}

	lbound = _nodesByParent.lower_bound(parentPtr);
	ubound = _nodesByParent.upper_bound(parentPtr);
}

Packet::Packet() {
	_edt = NULL;
	_wth = NULL;
	_cf = NULL;
	_nodeCounter = 0;
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

VALUE Packet::field_matches(VALUE self, VALUE query) {
	Packet* packet = NULL;
	Data_Get_Struct(self, Packet, packet);
	return packet->fieldMatches(query);
}

VALUE Packet::descendant_field_matches(VALUE self, VALUE parentField, VALUE query) {
	Packet* packet = NULL;
	Data_Get_Struct(self, Packet, packet);
	return packet->descendantFieldMatches(parentField, query);
}

VALUE Packet::find_first_field_match(VALUE self, VALUE query) {
	Packet* packet = NULL;
	Data_Get_Struct(self, Packet, packet);
	return packet->findFirstFieldMatch(query);
}

VALUE Packet::each_field_match(VALUE self, VALUE query) {
	Packet* packet = NULL;
	Data_Get_Struct(self, Packet, packet);
	return packet->eachFieldMatch(query);
}

VALUE Packet::find_first_descendant_field_match(VALUE self, VALUE parentField, VALUE query) {
	Packet* packet = NULL;
	Data_Get_Struct(self, Packet, packet);
	return packet->findFirstDescendantFieldMatch(parentField, query);
}

VALUE Packet::each_descendant_field_match(VALUE self, VALUE parentField, VALUE query) {
	Packet* packet = NULL;
	Data_Get_Struct(self, Packet, packet);
	return packet->eachDescendantFieldMatch(parentField, query);
}

void Packet::buildPacket() {
	//Add each of this packet's nodes to our node map
	_nodeCounter = 0;
	addProtocolNodes(_edt->tree);
}

void Packet::addNode(proto_node* node) {
	//Add this node to the node map in two ways: by its header name,
	//and by its parent's pointer value.  This allows access to fields by name
	//and by parent field

	//Find the ProtocolTreeNode object that wraps node->parent
	ProtocolTreeNode* parentNode = NULL;

	//If the node's parent is the tree object itself, that means it's a root node, and thus
	//has no parent as far as we're concerned.  Otherwise, it should have a previously-processed parent node
	if (node->parent != _edt->tree) {
		parentNode = getProtocolTreeNodeFromProtoNode(node->parent);

		if (parentNode == NULL) {
			//Hmm, that shouldn't happen
			::rb_bug("Processing node within packet and unable to find parent ProtocolTreeNode object for a given proto_node");
		}
	}

	ProtocolTreeNode* nodeStruct = new ProtocolTreeNode(_self, _edt, _nodeCounter++, node, parentNode);

	_nodesByName.insert(NodeNameMap::value_type(nodeStruct->getName(), nodeStruct));
	_nodesByParent.insert(NodeParentMap::value_type((guint64)node->parent, nodeStruct));
}
	
VALUE Packet::getRubyFieldObjectForField(ProtocolTreeNode& node) {
	return node.getFieldObject();
}

void Packet::mark() {
	//Mark all the Ruby Field objects we know about
	for (NodeNameMap::const_iterator iter = _nodesByName.begin();
		iter != _nodesByName.end();
		++iter) {
		if (!NIL_P(iter->second->peekFieldObject())) {
			::rb_gc_mark(iter->second->peekFieldObject());
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

VALUE Packet::descendantFieldExists(VALUE parentField, VALUE fieldName) {
	//Look for the given field name in the descendants of this field
	if (NIL_P(parentField)) return Qfalse;

	const gchar* name = RSTRING(::StringValue(fieldName))->ptr;

	Field* field = NULL;
	Data_Get_Struct(parentField, Field, field);

	if (findDescendantNodeByName(field->getProtoNode(),
		name)) {
		return Qtrue;
	} else {
		return Qfalse;
	}
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

	sortAndYield(lbound, ubound);

	return _self;
}

VALUE Packet::findFirstDescendantField(VALUE parentField, VALUE fieldName) {
	//Look for the given field name in the descendants of this field
	if (NIL_P(parentField))  {
		::rb_raise(::rb_eArgError, "parentField cannot be nil");
	}

	SafeStringValue(fieldName);
	const gchar* name = RSTRING(fieldName)->ptr;
	if (!name) {
		return Qnil;
	}

	Field* field = NULL;
	Data_Get_Struct(parentField, Field, field);

	return findDescendantFieldByName(field->getProtoNode(), name);
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

	ProtocolTreeNodeOrderedSet sorted;
	findDescendantFieldByName(parentFieldPtr->getProtoNode(), fieldName, sorted);

	sortAndYield(sorted.begin(),
		sorted.end());

	return _self;
}
	
VALUE Packet::fieldMatches(VALUE query) {
	VALUE fieldQuery = FieldQuery::createFieldQuery(_self);
	for (NodeNameMap::iterator iter = _nodesByName.begin();
		iter != _nodesByName.end();
		++iter) {
		FieldQuery::setFieldQueryCurrentNode(fieldQuery, iter->second);
		if (FieldQuery::passFieldToProc(fieldQuery, query)) {
			//This field matched the query
			return Qtrue;
		}
	}

	//No field matched the query, so the answer is no
	return Qfalse;
}

VALUE Packet::descendantFieldMatches(VALUE parentField, VALUE query) {
	//Look for the given field name in the descendants of this field
	if (NIL_P(parentField))  {
		::rb_raise(::rb_eArgError, "parentField cannot be nil");
	}

	VALUE fieldQuery = FieldQuery::createFieldQuery(_self);

	Field* field = NULL;
	Data_Get_Struct(parentField, Field, field);
	if (findDescendantNodeByQuery(field->getProtoNode(), fieldQuery, query)) {
		return Qtrue;
	} else {
		return Qfalse;
	}
}

VALUE Packet::findFirstFieldMatch(VALUE query) {
	VALUE fieldQuery = FieldQuery::createFieldQuery(_self);

	for (NodeNameMap::iterator iter = _nodesByName.begin();
		iter != _nodesByName.end();
		++iter) {
		FieldQuery::setFieldQueryCurrentNode(fieldQuery, iter->second);
		if (FieldQuery::passFieldToProc(fieldQuery, query)) {
			//This field matched the query
			return getRubyFieldObjectForField(*iter->second);
		}
	}

	//No field matched
	return Qnil;
}

VALUE Packet::eachFieldMatch(VALUE query) {
	rb_need_block();
	VALUE fieldQuery = FieldQuery::createFieldQuery(_self);

	ProtocolTreeNodeOrderedSet sorted;

	for (NodeNameMap::iterator iter = _nodesByName.begin();
		iter != _nodesByName.end();
		++iter) {
		FieldQuery::setFieldQueryCurrentNode(fieldQuery, iter->second);
		if (FieldQuery::passFieldToProc(fieldQuery, query)) {
			//This field matched the query
			sorted.insert(iter->second);
		}
	}

	//Yield all of the matches
	sortAndYield(sorted.begin(),
		sorted.end());

	return _self;
}

VALUE Packet::findFirstDescendantFieldMatch(VALUE parentField, VALUE query) {
	//Look for the given field name in the descendants of this field
	if (NIL_P(parentField))  {
		::rb_raise(::rb_eArgError, "parentField cannot be nil");
	}

	Field* field = NULL;
	Data_Get_Struct(parentField, Field, field);
	VALUE fieldQuery = FieldQuery::createFieldQuery(_self);
	return findDescendantFieldByQuery(field->getProtoNode(),
		fieldQuery,
		query);
}

VALUE Packet::eachDescendantFieldMatch(VALUE parentField, VALUE query) {
	if (NIL_P(parentField))  {
		::rb_raise(::rb_eArgError, "parentField cannot be nil");
	}

	rb_need_block();

	Field* parentFieldPtr = NULL;
	Data_Get_Struct(parentField, Field, parentFieldPtr);
	VALUE fieldQuery = FieldQuery::createFieldQuery(_self);

	ProtocolTreeNodeOrderedSet sorted;

	findDescendantFieldByQuery(parentFieldPtr->getProtoNode(),
		fieldQuery,
		query,
		sorted);

	sortAndYield(sorted.begin(),
		sorted.end());

	return _self;
}

ProtocolTreeNode* Packet::getProtocolTreeNodeFromProtoNode(proto_node* node) {
	//If the wrapper for this node is known to the packet, it will be in the list
	//of ProtocolTreeNode objects who share node's parent.  Thus, like there
	NodeParentMap::iterator lbound, ubound;
	lbound = _nodesByParent.lower_bound((guint64)node->parent);
	ubound = _nodesByParent.upper_bound((guint64)node->parent);

	for (NodeParentMap::iterator iter = lbound;
		iter != ubound;
		++iter) {
		if (iter->second->getProtoNode() == node) {
			return iter->second;
		}
	}

	return NULL;
}

void Packet::addProtocolNodes(proto_tree *tree) {
	proto_node *pnode = tree;
	proto_node *child;
	proto_node *current;

	child = pnode->first_child;

	while (child != NULL) {
		current = child;
		child = current->next;

		//Pass this node to the callback
		addNode(current);

		//Now process all this node's children
		addProtocolNodes((proto_tree *)current);
	}
}

ProtocolTreeNode* Packet::findDescendantNodeByName(ProtocolTreeNode* parent, const gchar* name) {
	NodeParentMap::iterator lbound = _nodesByParent.lower_bound((guint64)parent->getProtoNode());
	NodeParentMap::iterator ubound = _nodesByParent.upper_bound((guint64)parent->getProtoNode());
	for (NodeParentMap::iterator iter = lbound;
		iter != ubound;
		++iter) {
		if (name == NULL ||
			::strcmp(name, iter->second->getName()) == 0) {
			//Found it
			return iter->second;
		}

		//Else, search children
		ProtocolTreeNode* match = findDescendantNodeByName(iter->second, name);
		if (match) {
			return match;
		}
	}

	return NULL;
}

VALUE Packet::findDescendantFieldByName(ProtocolTreeNode* parent, const gchar* name) {
	ProtocolTreeNode* match = findDescendantNodeByName(parent, name);

	if (match) {
		return getRubyFieldObjectForField(*match);
	}

	return Qnil;
}

void Packet::findDescendantFieldByName(ProtocolTreeNode* parent, const gchar* name, ProtocolTreeNodeOrderedSet& set) {
	NodeParentMap::iterator lbound = _nodesByParent.lower_bound((guint64)parent->getProtoNode());
	NodeParentMap::iterator ubound = _nodesByParent.upper_bound((guint64)parent->getProtoNode());
	for (NodeParentMap::iterator iter = lbound;
		iter != ubound;
		++iter) {
		if (name == NULL ||
			::strcmp(name, iter->second->getName()) == 0) {
			//Found it
			set.insert(iter->second);
		}

		//Search children
		findDescendantFieldByName(iter->second, name, set);
	}
}

ProtocolTreeNode* Packet::findDescendantNodeByQuery(ProtocolTreeNode* parent, VALUE fieldQueryObject, VALUE query) {
	NodeParentMap::iterator lbound = _nodesByParent.lower_bound((guint64)parent->getProtoNode());
	NodeParentMap::iterator ubound = _nodesByParent.upper_bound((guint64)parent->getProtoNode());
	for (NodeParentMap::iterator iter = lbound;
		iter != ubound;
		++iter) {
		FieldQuery::setFieldQueryCurrentNode(fieldQueryObject, iter->second);
		if (FieldQuery::passFieldToProc(fieldQueryObject, query)) {
			//Found it
			return iter->second;
		}

		//Else, search children
		ProtocolTreeNode* match = findDescendantNodeByQuery(iter->second, fieldQueryObject, query);
		if (match) {
			return match;
		}
	}

	return NULL;
}

VALUE Packet::findDescendantFieldByQuery(ProtocolTreeNode* parent, VALUE fieldQueryObject, VALUE query) {
	ProtocolTreeNode* match = findDescendantNodeByQuery(parent, fieldQueryObject, query);
	if (match) {
		return getRubyFieldObjectForField(*match);
	}

	return Qnil;
}

void Packet::findDescendantFieldByQuery(ProtocolTreeNode* parent, VALUE fieldQueryObject, VALUE query, ProtocolTreeNodeOrderedSet& set) {
	NodeParentMap::iterator lbound = _nodesByParent.lower_bound((guint64)parent->getProtoNode());
	NodeParentMap::iterator ubound = _nodesByParent.upper_bound((guint64)parent->getProtoNode());
	for (NodeParentMap::iterator iter = lbound;
		iter != ubound;
		++iter) {
		FieldQuery::setFieldQueryCurrentNode(fieldQueryObject, iter->second);
		if (FieldQuery::passFieldToProc(fieldQueryObject, query)) {
			//Found it
			set.insert(iter->second);
		}

		//Search children
		findDescendantFieldByQuery(iter->second, fieldQueryObject, query, set);
	}
}
