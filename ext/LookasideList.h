#pragma once

#ifdef USE_LOOKASIDE_LIST

#include <deque>

#include "Allocator.h"

//#define VERBOSE_DEBUG //Uncomment for additional debugging output

/** Abstract base class for typed lookaside lists that maintain a pool of pre-allocated memory blocks */
template<typename _T>
class LookasideList {
public:
	/** Creates a new lookaside list, initializing the pool with initialObjectPoolSize memory blocks,
	which will store no more than maxObjectPoolSize objects in the pool before it starts freeing them */
	LookasideList(Allocator& allocator, size_t initialObjectPoolSize, size_t maxObjectPoolSize) : 
		_allocator(allocator),
		_initialObjectPoolSize(initialObjectPoolSize),
		_maxObjectPoolSize(maxObjectPoolSize) {
#ifdef VERBOSE_DEBUG
		_numOutstandingBlocks = 0;
		_maxNumOutstandingBlocks = 0;
#endif
		while (_pool.size() < _initialObjectPoolSize) {
			_pool.push_front(allocateBlock());
		}
	}

	virtual ~LookasideList() {
		while (_pool.size()) {
			_T* block = _pool.front();
			freeBlock(block);
			_pool.pop_front();
		}
	}

protected:
	/** Gets a block from the pool if available, otherwise allocates a new block for that purpose */
	_T* getBlock() {
#ifdef VERBOSE_DEBUG
		_numOutstandingBlocks++;
		if (_numOutstandingBlocks > _maxNumOutstandingBlocks) {
			::printf("New high water mark for outstanding blocks: %d blocks\n",
				_numOutstandingBlocks);
			_maxNumOutstandingBlocks = _numOutstandingBlocks;
		}
#endif
		if (_pool.size()) {
			//Just pull something off the pool
			_T* block = _pool.front();
			_pool.pop_front();
			return block;
		}

		//Else, nothing in the pool, so get it straight from the allocator
		return allocateBlock();
	}

	/** Returns a block obtained with getBlock back to the pool, or frees it immediately
	if the pool is full */
	void returnBlock(_T* block) {
#ifdef VERBOSE_DEBUG
		_numOutstandingBlocks--;
#endif

		if (_pool.size() < _maxObjectPoolSize) {
			//Room in the pool for this object
			_pool.push_front(block);
		} else {
			//Pool is full; just free
			freeBlock(block);
		}
	}

private:
	typedef std::deque<_T*> ObjectDeque;

	//No copy ctor, and no assignment
	LookasideList() {}
	LookasideList& operator=(const LookasideList& rhs) {
		return *this;
	}

	_T* allocateBlock() {
		return reinterpret_cast<_T*>(_allocator.allocate(sizeof(_T)));
	}

	void freeBlock(_T* block) {
		_allocator.free(block);
	}

	Allocator& _allocator;
	size_t _initialObjectPoolSize;
	size_t _maxObjectPoolSize;
	ObjectDeque _pool;

#ifdef VERBOSE_DEBUG
	size_t _numOutstandingBlocks;
	size_t _maxNumOutstandingBlocks;
#endif
};

#endif
