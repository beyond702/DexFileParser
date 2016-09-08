#include "DexFileParser.h"
#include "DexProto.h"
#include "Leb128.h"
#include "DexCatch.h"

#include <stdlib.h>
#include <string.h>


DexFileParser::DexFileParser(const char* dex_cont, int dex_len)
	: dex_file(NULL)
{
	dex = (char*)malloc(dex_len);
	memcpy(dex, dex_cont, dex_len);
}

DexFileParser::~DexFileParser()
{
	if(dex_file)
		delete dex_file;

	if(dex)
		free(dex);
}

void DexFileParser::dexParseFile()
{
	if(dex_file) {
		printf("dexParseFile has been done already\n");
		return;
	}

	DexHeader* header = (DexHeader*)dex;

	dex_file = new DexFile;

	dex_file->pClassLookup = NULL;
	dex_file->pOptHeader = NULL;
	dex_file->pRegisterMapPool = NULL;

	dex_file->baseAddr = (u1*)dex;

	dex_file->pHeader = header;

	dex_file->pStringIds = (DexStringId*)(dex + header->stringIdsOff);
	dex_file->pTypeIds = (DexTypeId*)(dex + header->typeIdsOff);
	dex_file->pFieldIds = (DexFieldId*)(dex + header->fieldIdsOff);
	dex_file->pMethodIds = (DexMethodId*)(dex + header->methodIdsOff);
	dex_file->pProtoIds = (DexProtoId*)(dex + header->protoIdsOff);
	dex_file->pClassDefs = (DexClassDef*)(dex + header->classDefsOff);
	dex_file->pLinkData = (DexLink*)(dex + header->linkOff);

#if 1
	dumpDexHeader(header);

	dumpMapList((DexMapList*)(dex + header->mapOff));
	printf("\n");
	printf("\n");

#if 0

	const char* str = getStringById(dex_file, 6);
	printf("String(6): %s\n", str);

	DexTypeId* type = getTypeId(dex_file, 0);
	str = getStringById(dex_file, type->descriptorIdx);
	printf("Type(0/%X): %s\n", type->descriptorIdx, str);

	DexFieldId* field = getFieldId(dex_file, 4164);
	const char* name_str = getStringById(dex_file, field->nameIdx);
	const char* class_str = getStringByTypeId(dex_file, field->classIdx);
	const char* type_str = getStringByTypeId(dex_file, field->typeIdx);
	printf("Field(0): name(%s), class(%s), type(%s)\n", name_str, class_str, type_str);

	DexMethodId* method = getMethodId(dex_file, 0);
	name_str = getStringById(dex_file, method->nameIdx);
	class_str = getStringByTypeId(dex_file, method->classIdx);
	printf("Method(0): name(%s), class(%s)\n", name_str, class_str);

	DexProtoId* proto = getProtoId(dex_file, 30);
	name_str = getStringById(dex_file, proto->shortyIdx);
	const char* returntype_str = getStringByTypeId(dex_file, proto->returnTypeIdx);
	printf("Proto(0): name(%s), return type(%s), parameters:\n", name_str, returntype_str);

	DexTypeList* type_list = getProtoParameters(dex_file, proto);
	if (type_list != NULL)
		for (int i = 0; i < type_list->size; i++) {
			type = getTypeId(dex_file, type_list->list[i].typeIdx);
			printf("  [%d/%d] %s\n", i, type_list->size,
					getStringById(dex_file, type->descriptorIdx));
		}
	printf("\n");
#endif


	for(int i = 0; i < header->classDefsSize; i++) {
		dumpClass(i);
	}

#endif
}


void DexFileParser::dumpDexHeader(DexHeader* header)
{
	printf("magic: %c%c%c%c%c%c%c%c\n",
			header->magic[0], header->magic[1],header->magic[2],header->magic[3],
			header->magic[4], header->magic[5],header->magic[6],header->magic[7]);

	printf("mapOff %X\n"
			"stringIdsOff %X, size %d\n"
			"typeIdsOff %X, size %d\n"
			"protoIdsOff %X, size %d\n"
			"fieldIdsOff %X, size %d\n"
			"methodIdsOff %X, size %d\n"
			"classDefsOff %X, size %d\n"
			"dataOff %X, size %d\n",
			header->mapOff, header->stringIdsOff, header->stringIdsSize,
			header->typeIdsOff, header->typeIdsSize,
			header->protoIdsOff, header->protoIdsSize,
			header->fieldIdsOff, header->fieldIdsSize,
			header->methodIdsOff, header->methodIdsSize,
			header->classDefsOff, header->classDefsSize,
			header->dataOff, header->dataSize);
}

const char* getMapItemTypeStr(uint16_t i)
{
	switch (i) {
	case 0x0000:
		return "kDexTypeHeaderItem";
	case 0x0001:
		return "kDexTypeStringIdItem";
	case 0x0002:
		return "kDexTypeTypeIdItem";
	case 0x0003:
		return "kDexTypeProtoIdItem";
	case 0x0004:
		return "kDexTypeFieldIdItem";
	case 0x0005:
		return "kDexTypeMethodIdItem";
	case 0x0006:
		return "kDexTypeClassDefItem";
	case 0x1000:
		return "kDexTypeMapList";
	case 0x1001:
		return "kDexTypeTypeList";
	case 0x1002:
		return "kDexTypeAnnotationSetRefList";
	case 0x1003:
		return "kDexTypeAnnotationSetItem";
	case 0x2000:
		return "kDexTypeClassDataItem";
	case 0x2001:
		return "kDexTypeCodeItem";
	case 0x2002:
		return "kDexTypeStringDataItem";
	case 0x2003:
		return "kDexTypeDebugInfoItem";
	case 0x2004:
		return "kDexTypeAnnotationItem";
	case 0x2005:
		return "kDexTypeEncodedArrayItem";
	case 0x2006:
		return "kDexTypeAnnotationsDirectoryItem";
	default:
		return "NULL";
	}
}
void DexFileParser::dumpMapList(DexMapList* p)
{
	int cnt = p->size;

	printf("\nMapItemList:\n");
	for(int i = 0; i < cnt; i++) {
		DexMapItem* item = (DexMapItem*)(p->list + i);
		printf("\t[%d] type %s, size %d, offset %X\n", i, getMapItemTypeStr(item->type), item->size, item->offset);
	}
}


void DexFileParser::dumpClass(int idx)
{
	DexClassDef* class_def = getClassDef(dex_file, idx);
	const char* class_str = getStringByTypeId(dex_file, class_def->classIdx);
#if 0
	if (strstr(class_str, "Lcom/example/cert") == NULL)
		return;
#endif

	const char* super_str = getStringByTypeId(dex_file, class_def->superclassIdx);
	const char* src_str = getStringById(dex_file, class_def->sourceFileIdx);

	printf("\nClass[%d]: name(%s), super(%s), source file(%s)\n",
			idx, class_str, super_str, src_str);

	DexClassData* class_data  = getClassData(dex_file, class_def);
	if (class_data != NULL) {
		printf("\tcontains field(%d/%d) method (%d/%d):\n",
				class_str, class_data->header.staticFieldsSize, class_data->header.instanceFieldsSize,
				class_data->header.directMethodsSize, class_data->header.virtualMethodsSize);

		DexTypeList* interfaces = getInterfaces(dex_file, class_def);
		if (interfaces != NULL)
			for (int i = 0; i < interfaces->size; i++) {
				DexTypeId* interface = getTypeId(dex_file, interfaces->list[i].typeIdx);
				printf("\tinterface[%d]: %s\n", i,
						getStringById(dex_file, interface->descriptorIdx));
			}

		DexField* class_field = class_data->staticFields;
		if (class_field != NULL)
			for (int i = 0; i < class_data->header.staticFieldsSize; i++) {
				DexFieldId* field = getFieldId(dex_file, class_field[i].fieldIdx);
				printf("\tstatic Field[%d]: %s\n", i, getStringById(dex_file, field->nameIdx));
			}
		class_field = class_data->instanceFields;
		if (class_field != NULL)
			for (int i = 0; i < class_data->header.instanceFieldsSize; i++) {
				DexFieldId* field = getFieldId(dex_file, class_field[i].fieldIdx);
				printf("\tinstance Field[%d]: %s\n", i, getStringById(dex_file, field->nameIdx));
			}

		DexMethod* class_method = class_data->directMethods;
		if (class_method != NULL)
			for (int i = 0; i < class_data->header.directMethodsSize; i++) {
				DexMethod* method = &class_method[i];
				dumpMethod(method);
			}

		free(class_data);
	}
}

void DexFileParser::dumpMethod(DexMethod* method)
{
	DexMethodId* method_id = getMethodId(dex_file, method->methodIdx);
	printf("\tMethod: %s\n", getStringById(dex_file, method_id->nameIdx));

	DexProtoId* proto = getProtoId(dex_file, method_id->protoIdx);
	const char* shorty = getStringById(dex_file, proto->shortyIdx);
	const char* ret_type = getStringByTypeId(dex_file, proto->returnTypeIdx);
	printf("\t\tshorty: %s, ret_type: %s\n", shorty, ret_type);
	DexTypeList* type_list = getProtoParameters(dex_file, proto);
//	for(int i = 0; i < type_list->size; i++)
//		printf("\t\tparameter: %s\n", getStringById(getTypeId(type_list->list[i].typeIdx)->descriptorIdx));

	DexCode* code = getMethodDexCode(dex_file, method);
	dumpCode(code);

#if 0
	for (int i = 0; i < code->insnsSize; i++)
		printf("\t\t\tinsns[%d]: %X\n", i, code->insns[i]);
#endif

	dumpCatches(code);

	dumpPositions(code, method);
	dumpLocals(code, method);
}

void DexFileParser::dumpCode(DexCode* code)
{
	printf( "\t\tregisterSize %d, insSize %d, outsSize %d, triesSize %d, debugInfoOff %X, insnsSize %d\n",
			code->registersSize, code->insSize, code->outsSize,
			code->triesSize, code->debugInfoOff, code->insnsSize);
}

void DexFileParser::dumpCatches(DexCode* code)
{
	printf("\t\tcatches:\n");

	u4 triesSize = code->triesSize;
	if(triesSize == 0) {
		return;
	}

	const u2* ptr = &code->insns[code->insnsSize];
	if(((uintptr_t)ptr & 0x3) != 0)
		ptr++;

	const DexTry* pDexTries = (const DexTry*)ptr;

	for(u4 i = 0; i < code->triesSize; i++) {
		const DexTry* pDexTry = &pDexTries[i];
		u4 startAddr = pDexTry->startAddr;
		u4 endAddr = startAddr + pDexTry->insnCount;

		printf("\t\t\t0x%04X - 0x%04X\n", startAddr, endAddr);

		DexCatchIterator iterator;
		iterator.pEncodedData = (const u1*)(&pDexTries[code->triesSize]) + pDexTry->handlerOff;
		int count = readUnsignedLeb128(&iterator.pEncodedData);
		if(count <= 0)
			iterator.catchesAll = true;
		else
			iterator.catchesAll = false;
		iterator.countRemaining = count;

		for(;;) {
			DexCatchHandler* handler = dexCatchIteratorNext(&iterator);
			if(handler == NULL)
				break;

			const char* descriptor = (handler->typeIdx == kDexNoIndex) ? "<any>" :
					getStringByTypeId(dex_file, handler->typeIdx);
			printf("\t\t\t\thandler(%s), addr(0x%04X)\n", descriptor, handler->address);
		}
	}
}

void DexFileParser::dumpPositions(DexCode* code, DexMethod* method)
{
	printf("\t\tpositions:\n");
	DexMethodId* pMethodId = getMethodId(dex_file, method->methodIdx);
	const char* pClassDescriptor = getStringByTypeId(dex_file, pMethodId->classIdx);

	decodeDebugInfo(code, pClassDescriptor, pMethodId->protoIdx, method->accessFlags, true, false);
}

void DexFileParser::dumpLocals(DexCode* code, DexMethod* method)
{
	printf("\t\tLocals:\n");
	DexMethodId* pMethodId = getMethodId(dex_file, method->methodIdx);
	const char* pClassDescriptor = getStringByTypeId(dex_file, pMethodId->classIdx);

	decodeDebugInfo(code, pClassDescriptor, pMethodId->protoIdx, method->accessFlags, false, true);
}

struct LocalInfo {
	const char* name;
	const char* descriptor;
	const char* signature;
	u2 startAddress;
	bool live;
};

const char* DexFileParser::readStringIdx(DexFile* pDexFile, const u1** pStream)
{
	int stringIdx = readUnsignedLeb128(pStream);

	if(stringIdx == 0)
		return NULL;
	else
		return getStringById(pDexFile, stringIdx-1);
}

const char* DexFileParser::readTypeIdx(DexFile* pDexFile, const u1** pStream)
{
	int typeIdx = readUnsignedLeb128(pStream);

	if(typeIdx == 0)
		return NULL;
	else
		return getStringByTypeId(pDexFile, typeIdx-1);
}

void DexFileParser::decodeDebugInfo(DexCode* pCode, const char* pClassDescriptor,
		int protoIdx, int accessFlags, bool dumpPosition, bool dumpLocal)
{
	if(pCode->debugInfoOff == 0)
		return;

	const u1* pStream = dex_file->baseAddr + pCode->debugInfoOff;

	LocalInfo localInReg[pCode->registersSize];
	memset(localInReg, 0, sizeof(LocalInfo)*pCode->registersSize);

	int line = readUnsignedLeb128(&pStream);
	int parametersSize = readUnsignedLeb128(&pStream);
	int address = 0;
	DexProto proto = {dex_file, protoIdx};
	int argRegSize = pCode->registersSize - pCode->insSize;

	if((accessFlags & ACC_STATIC) == 0) {
		localInReg[argRegSize].descriptor = pClassDescriptor;
		localInReg[argRegSize].name = "this";
		localInReg[argRegSize].startAddress = address;
		localInReg[argRegSize].live = true;
		argRegSize++;
	}

	DexParameterIterator iterator;
	iterator.proto = &proto;
	iterator.parameters = getProtoParameters(dex_file, getProtoId(dex_file, protoIdx));
	iterator.parameterCount = iterator.parameters != NULL ? iterator.parameters->size : 0;
	iterator.cursor = 0;

	while(parametersSize-- != 0) {
		const char* descriptor = dexParameterIteratorNextDescriptor(&iterator);
		const char* name;
		int reg;

		if(argRegSize >= pCode->registersSize || descriptor == NULL)
			return;

		//Remember, encoded string indicies have 1 added to them
		name = readStringIdx(dex_file, &pStream);
		reg = argRegSize;

		switch(descriptor[0]) {
		case 'D':
		case 'J':
			argRegSize += 2;
			break;
		default:
			argRegSize++;
			break;
		}

		if(name != NULL) {
			localInReg[reg].descriptor = descriptor;
			localInReg[reg].name = name;
			localInReg[reg].startAddress = address;
			localInReg[reg].signature = NULL;
			localInReg[reg].live = true;
		}
	}

	for(;;) {
		u1 opcode = *pStream++;
		u2 reg;

		switch(opcode) {
		case DBG_END_SEQUENCE:
			goto end;
		case DBG_ADVANCE_PC:
			address += readUnsignedLeb128(&pStream);
			break;
		case DBG_ADVANCE_LINE:
			line += readSignedLeb128(&pStream);
			break;
		case DBG_START_LOCAL:
		case DBG_START_LOCAL_EXTENDED:
			reg = readUnsignedLeb128(&pStream);
			if(reg >= pCode->registersSize)
				goto end;

			if(localInReg[reg].live && dumpLocal)
				printf("\t\t\taddress 0x%04X - 0x%04X, reg(%d), name(%s), descriptor(%s), signature(%s)\n",
						localInReg[reg].startAddress, address, reg, localInReg[reg].name,
						localInReg[reg].descriptor, localInReg[reg].signature);

			localInReg[reg].name = readStringIdx(dex_file, &pStream);
			localInReg[reg].descriptor = readTypeIdx(dex_file, &pStream);
			if(opcode == DBG_START_LOCAL_EXTENDED)
				localInReg[reg].signature = readStringIdx(dex_file, &pStream);
			else
				localInReg[reg].signature = NULL;

			localInReg[reg].startAddress = address;
			localInReg[reg].live = true;
			break;

		case DBG_END_LOCAL:
			reg = readUnsignedLeb128(&pStream);
			if(reg >= pCode->registersSize)
				goto end;

			if (dumpLocal)
				printf("\t\t\taddress 0x%04X - 0x%04X, reg(%d), name(%s), descriptor(%s), signature(%s)\n",
						localInReg[reg].startAddress, address, reg,
						localInReg[reg].name, localInReg[reg].descriptor, localInReg[reg].signature);

			localInReg[reg].live = false;
			break;
		case DBG_RESTART_LOCAL:
			reg = readUnsignedLeb128(&pStream);
			if(reg >= pCode->registersSize)
				goto end;

			if(localInReg[reg].name == NULL ||
					localInReg[reg].descriptor == NULL)
				goto end;

			if(!localInReg[reg].live) {
				localInReg[reg].startAddress = address;
				localInReg[reg].live = false;
			}
			break;
		case DBG_SET_EPILOGUE_BEGIN:
		case DBG_SET_PROLOGUE_END:
		case DBG_SET_FILE:
			break;
		default: {
			int adjopcode = opcode - DBG_FIRST_SPECIAL;
			address += adjopcode / DBG_LINE_RANGE;
			line += DBG_LINE_BASE + (adjopcode % DBG_LINE_RANGE);

			if (dumpPosition)
				printf("\t\t\taddress: 0x%04X, line %d\n", address, line);
		}
			break;
		}
	}

end:
	for(int reg = 0; reg < pCode->registersSize; reg++)
		if(localInReg[reg].live && dumpLocal)
			printf("\t\t\taddress 0x%04X - 0x%04X, reg(%d), name(%s), descriptor(%s), signature(%s)\n",
								localInReg[reg].startAddress, address, reg, localInReg[reg].name,
								localInReg[reg].descriptor, localInReg[reg].signature);
}
