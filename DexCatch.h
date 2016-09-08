/*
 * Copyright (C) 2008 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Functions for dealing with try-catch info.
 */

#ifndef LIBDEX_DEXCATCH_H_
#define LIBDEX_DEXCATCH_H_

#include "DexFile.h"
#include "Leb128.h"

/*
 * Catch handler entry, used while iterating over catch_handler_items.
 */
struct DexCatchHandler {
    u4          typeIdx;    /* type index of the caught exception type */
    u4          address;    /* handler address */
};


/*
 * Iterator over catch handler data. This structure should be treated as
 * opaque.
 */
struct DexCatchIterator {
    const u1* pEncodedData;
    bool catchesAll;
    u4 countRemaining;
    DexCatchHandler handler;
};

DEX_INLINE DexCatchHandler* dexCatchIteratorNext(DexCatchIterator* pIterator)
{
	if(pIterator->countRemaining == 0) {
		if(!pIterator->catchesAll)
			return NULL;

		pIterator->catchesAll = false;
		pIterator->handler.typeIdx = kDexNoIndex;
	} else {
		u4 typeIdx = readUnsignedLeb128(&pIterator->pEncodedData);
		pIterator->handler.typeIdx = typeIdx;
		pIterator->countRemaining--;
	}

	pIterator->handler.address = readUnsignedLeb128(&pIterator->pEncodedData);
	return &pIterator->handler;
}

#endif  // LIBDEX_DEXCATCH_H_
