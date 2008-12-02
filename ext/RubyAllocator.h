#ifndef RUBY_ALLOCATOR_H
#define RUBY_ALLOCATOR_H

#include "Allocator.h"

#ifdef USE_LOOKASIDE_LIST
/** Allocator implementation that uses the Ruby memory allocation functions which are GC-aware */
class RubyAllocator : public Allocator
{
public:
	RubyAllocator(void);
	virtual ~RubyAllocator(void);

	virtual void* allocate(size_t numBytes);
	virtual void free(void* block);
};
#endif


#endif /* RUBY_ALLOCATOR_H */

