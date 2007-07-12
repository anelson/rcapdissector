#pragma once

#ifdef USE_LOOKASIDE_LIST

#include "LookasideList.h"
#include "ProtocolTreeNode.h"

/** Lookaside list that maintains a collection of memory blocks allocated for ProtocolTreeNode
objects.  Reduces reliance on the general-purpose heap manager which tends to suck wind */
class ProtocolTreeNodeLookasideList : public LookasideList<ProtocolTreeNode> {
public:
	ProtocolTreeNodeLookasideList(Allocator& allocator, size_t initialObjectPoolSize, size_t maxObjectPoolSize) : 
		LookasideList(allocator, initialObjectPoolSize, maxObjectPoolSize) {
	}
	virtual ~ProtocolTreeNodeLookasideList() {

	}

	ProtocolTreeNode* getProtocolTreeNode(VALUE packet, epan_dissect_t* edt, guint ordinal, proto_node* node, ProtocolTreeNode* parentNode) {
		//Get the uninitialized memory block from the lookaside list
		ProtocolTreeNode* protoNode = getBlock();
		if (!protoNode) {
			return NULL;
		}

		return new(protoNode) ProtocolTreeNode(packet, edt, ordinal, node, parentNode);
	}

	void returnProtocolTreeNode(ProtocolTreeNode* node) {
		//Have to manually call the dtor, since we won't be delete-ing this memory
		node->~ProtocolTreeNode();

		returnBlock(node);
	}
};

#endif
