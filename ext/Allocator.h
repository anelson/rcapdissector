#pragma once

#ifdef USE_LOOKASIDE_LIST
/** Abstract base class reprenting an interface to a heap allocation API */
class Allocator
{
public:
	Allocator(void);
	virtual ~Allocator(void);

	virtual void* allocate(size_t numBytes) = 0;
	virtual void free(void* block) = 0;
};
#endif
