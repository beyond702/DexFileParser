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
 * Functions for dealing with method prototypes
 */

#ifndef LIBDEX_DEXPROTO_H_
#define LIBDEX_DEXPROTO_H_

#include "DexFile.h"

/*
 * Single-thread single-string cache. This structure holds a pointer to
 * a string which is semi-automatically manipulated by some of the
 * method prototype functions. Functions which use in this struct
 * generally return a string that is valid until the next
 * time the same DexStringCache is used.
 */
struct DexStringCache {
    char* value;          /* the latest value */
    size_t allocatedSize; /* size of the allocated buffer, if allocated */
    char buffer[120];     /* buffer used to hold small-enough results */
};


/*
 * Method prototype structure, which refers to a protoIdx in a
 * particular DexFile.
 */
struct DexProto {
    const DexFile* dexFile;     /* file the idx refers to */
    u4 protoIdx;                /* index into proto_ids table of dexFile */
};


/*
 * Single-thread prototype parameter iterator. This structure holds a
 * pointer to a prototype and its parts, along with a cursor.
 */
struct DexParameterIterator {
    const DexProto* proto;
    const DexTypeList* parameters;
    int parameterCount;
    int cursor;
};

DEX_INLINE const char* dexParameterIteratorNextDescriptor(DexParameterIterator* iterator)
{
	if(iterator->cursor >= iterator->parameterCount)
		return NULL;

	const DexTypeItem *item = &iterator->parameters->list[iterator->cursor];
	iterator->cursor++;

	return getStringById(iterator->proto->dexFile, getTypeId(iterator->proto->dexFile, item->typeIdx)->descriptorIdx);
}

#endif  // LIBDEX_DEXPROTO_H_
