#pragma once

#include <map>
#include <string>
#include <set>

#include "RubyAndShit.h"

#include "rcapdissector.h"

#include "ProtocolTreeNode.h"
#ifdef USE_LOOKASIDE_LIST
#include "RubyAllocator.h"
#include "ProtocolTreeNodeLookasideList.h"
#endif

class Packet
{
public:
	/** Contains fields keyed by their name */
	typedef std::multimap<std::string, ProtocolTreeNode*> NodeNameMap;

	/** Contains nodes keyed by their parent node's memory address */
	typedef std::multimap<guint64, ProtocolTreeNode*> NodeParentMap;

	static VALUE createClass();

	/** Gets the next packet from a capfile object, returning false if the end of the capfile is reached */
	static gboolean getNextPacket(VALUE capFileObject, capture_file& cf, VALUE& packet);

	/** Frees the native resources associated with a Ruby Packet object */
	static void freePacket(VALUE packet);

	epan_dissect_t* getEpanDissect() { return _edt; }

	/** Gets the range of nodes, including the given node and any siblings nodes, which share the same parent node */
	void getNodeSiblings(ProtocolTreeNode& node, NodeParentMap::iterator& lbound, NodeParentMap::iterator& ubound);

	/** Finds the ProtocolTreeNode wrapper for a given proto_node */
	ProtocolTreeNode* getProtocolTreeNodeFromProtoNode(proto_node* node);

	/** Releases the protocol tree nodes allocated for this packet.  Needs to happen before
	CapFile is GC'd if using lookaside list*/
	void free();

private:
	/** A version of the less<> comparator that operates on ProtocolTreeNode pointers, using the ordinal to sort */
	class ProtocolTreeNodeLess {
	public:
		typedef ProtocolTreeNode* first_argument_type;
		typedef ProtocolTreeNode* second_argument_type;
		typedef bool result_type;

		ProtocolTreeNodeLess() 
		{}

		bool operator()(ProtocolTreeNode const* lhs, ProtocolTreeNode const* rhs) {
			return lhs->getOrdinal() < rhs->getOrdinal();
		}
	};

	typedef std::set<ProtocolTreeNode*, ProtocolTreeNodeLess> ProtocolTreeNodeOrderedSet;

	Packet();
	virtual ~Packet(void);

	const Packet& operator=(const Packet&) {
		//TODO: Implement
		return *this;
	}

	/** Applies whatever filter is outstanding, and if packet passes filter, creates a Ruby Packet object 
	and its corresponding native object */
	static VALUE processPacket(VALUE capFileObject, capture_file& cf, gint64 offset);

	/*@ Packet capture helper methods */
	static void fillInFdata(frame_data *fdata, capture_file& cf,
				  const struct wtap_pkthdr *phdr, gint64 offset);
	static void clearFdata(frame_data *fdata);

	/*@ Methods implementing the Packet Ruby object methods */
	static void free(void* p);
	static void mark(void* p);
	static VALUE alloc(VALUE klass);
	static VALUE initialize(VALUE self, VALUE capFileObject);
	static VALUE init_copy(VALUE copy, VALUE orig);

	static VALUE field_exists(VALUE self, VALUE fieldName);
	static VALUE descendant_field_exists(VALUE self, VALUE parentField, VALUE fieldName);
	static VALUE find_first_field(VALUE self, VALUE fieldName);
	static VALUE each_field(int argc, VALUE* argv, VALUE self);
	static VALUE find_first_descendant_field(VALUE self, VALUE parentField, VALUE fieldName);
	static VALUE each_descendant_field(int argc, VALUE* argv, VALUE self);
	static VALUE each_root_field(VALUE self);

	static VALUE field_matches(VALUE self, VALUE query);
	static VALUE descendant_field_matches(VALUE self, VALUE parentField, VALUE query);
	static VALUE find_first_field_match(VALUE self, VALUE query);
	static VALUE each_field_match(VALUE self, VALUE query);
	static VALUE find_first_descendant_field_match(VALUE self, VALUE parentField, VALUE query);
	static VALUE each_descendant_field_match(VALUE self, VALUE parentField, VALUE query);

	/*@ Instance methods that actually perform the Packet-specific work */
	void buildPacket();
	void addNode(proto_node* node);
	VALUE getRubyFieldObjectForField(ProtocolTreeNode& node);
	void mark();
	VALUE fieldExists(VALUE fieldName);
	VALUE descendantFieldExists(VALUE parentField, VALUE fieldName);
	VALUE findFirstField(VALUE fieldName);
	VALUE eachField(int argc, VALUE* argv);
	VALUE findFirstDescendantField(VALUE parentField, VALUE fieldName);
	VALUE eachDescendantField(int argc, VALUE* argv);
	VALUE eachRootField();
	
	VALUE fieldMatches(VALUE query);
	VALUE descendantFieldMatches(VALUE parentField, VALUE query);
	VALUE findFirstFieldMatch(VALUE query);
	VALUE eachFieldMatch(VALUE query);
	VALUE findFirstDescendantFieldMatch(VALUE parentField, VALUE query);
	VALUE eachDescendantFieldMatch(VALUE parentField, VALUE query);

	/** Recursive function that adds nodes in a protocol tree to the node list */
	void addProtocolNodes(proto_tree *tree);

	/** Recursive function that searches a branch of the protocol tree for a field of a given name */
	ProtocolTreeNode* findDescendantNodeByName(ProtocolTreeNode* parent, const gchar* name);

	/** Recursive function that searches a branch of the protocol tree for a field of a given name */
	VALUE findDescendantFieldByName(ProtocolTreeNode* parent, const gchar* name);

	/** Recursive function that searches a branch of the protocol tree and adds every field that matches to the set */
	void findDescendantFieldByName(ProtocolTreeNode* parent, const gchar* name, ProtocolTreeNodeOrderedSet& set);

	/** Recursive function that searches a branch of the protocol tree for a field matching a given query */
	ProtocolTreeNode* findDescendantNodeByQuery(ProtocolTreeNode* parent, VALUE fieldQueryObject, VALUE query);

	/** Recursive function that searches a branch of the protocol tree for a field matching a given query */
	VALUE findDescendantFieldByQuery(ProtocolTreeNode* parent, VALUE fieldQueryObject, VALUE query);

	/** Recursive function that searches a branch of the protocol tree and adds every field that matches to the set */
	void findDescendantFieldByQuery(ProtocolTreeNode* parent, VALUE fieldQueryObject, VALUE query, ProtocolTreeNodeOrderedSet& set);

	/** Sorts a range of ProtocolTreeNode* objects identified by iterators of Pair<>s, then calls rb_yield
	with the Field object for each node */
	template <typename T>
	void sortAndYield(T begin, T end) {
		ProtocolTreeNodeOrderedSet sorted;
		fillSetWithRange(begin, end, sorted);

		for (ProtocolTreeNodeOrderedSet::iterator iter = sorted.begin();
			iter != sorted.end();
			++iter) {
			::rb_yield(getRubyFieldObjectForField(*(*iter)));
		}
	}

	/** Specialization of sortAndYield for ProtocolTreeNodeOrderedSet iterators */
	void sortAndYield<>(ProtocolTreeNodeOrderedSet::iterator begin, ProtocolTreeNodeOrderedSet::iterator end) {
		for (ProtocolTreeNodeOrderedSet::iterator iter = begin;
			iter != end;
			++iter) {
			::rb_yield(getRubyFieldObjectForField(*(*iter)));
		}
	}

	/** Fills a ProtocolTreeNodeORderedSet with the ProtocolTreeNode objects from a range of iterators */
	template<typename T>
	void fillSetWithRange(T begin, T end, ProtocolTreeNodeOrderedSet& sorted) {
		while (begin != end) {
			sorted.insert(begin->second);
			++begin;
		}
	}

	VALUE _self;
	epan_dissect_t* _edt;
	frame_data _frameData;
	wtap* _wth;
	capture_file* _cf;
	NodeNameMap _nodesByName;
	NodeParentMap _nodesByParent;
	guint _nodeCounter;
#ifdef USE_LOOKASIDE_LIST
	ProtocolTreeNodeLookasideList* _nodeLookaside;
#endif
};
