#ifndef DEXFILEPARSER_H_
#define DEXFILEPARSER_H_

#include "DexFile.h"


class DexFileParser {
public:
	DexFileParser(const char* dex_cont, int dex_len);
	~DexFileParser();

	void dexParseFile();


public:

	/*************** Dump functions **************/

	void dumpDexHeader(DexHeader* header);

	void dumpMapList(DexMapList* p);

	void dumpClass(int idx);

	void dumpMethod(DexMethod* method);

	void dumpCode(DexCode* code);

	void dumpCatches(DexCode* code);

	void dumpPositions(DexCode* code, DexMethod* method);

	void dumpLocals(DexCode* code, DexMethod* method);

private:

	const char* readStringIdx(DexFile* pDexFile, const u1** pStream);

	const char* readTypeIdx(DexFile* pDexFile, const u1** pStream);

	void decodeDebugInfo(DexCode* pCode, const char* pClassDescriptor,
			int protoIdx, int accessFlags, bool dumpPosition, bool dumpLocal);

private:

	char* dex;

	DexFile* dex_file;
};

#endif
