#include "RubyAllocator.h"

#ifdef USE_LOOKASIDE_LIST

#include "RubyAndShit.h"

RubyAllocator::RubyAllocator(void)
{
}

RubyAllocator::~RubyAllocator(void)
{
}

void* RubyAllocator::allocate(size_t numBytes) {
	return ::xmalloc(static_cast<long>(numBytes));
}
void RubyAllocator::free(void* block) {
	::xfree(block);
}

#endif


