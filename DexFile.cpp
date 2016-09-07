#include "DexFile.h"
#include "Leb128.h"



DexClassData* getClassData(const DexFile* pDexFile, DexClassDef* class_def)
{
	if(class_def->classDataOff == 0)
		return NULL;

	DexClassDataHeader header;

	const u1* data = (u1*)(pDexFile->baseAddr + class_def->classDataOff);

	header.staticFieldsSize = readUnsignedLeb128(&data);
	header.instanceFieldsSize = readUnsignedLeb128(&data);
	header.directMethodsSize = readUnsignedLeb128(&data);
	header.virtualMethodsSize = readUnsignedLeb128(&data);

	int size = sizeof(DexClassData) +
			header.staticFieldsSize * sizeof(DexField) +
			header.instanceFieldsSize * sizeof(DexField) +
			header.directMethodsSize * sizeof(DexMethod) +
			header.virtualMethodsSize * sizeof(DexMethod);

	DexClassData* class_data = (DexClassData*)malloc(size);

	class_data->header = header;

	u1* ptr = (u1*)class_data + sizeof(DexClassData);
	if(header.staticFieldsSize != 0) {
		class_data->staticFields = (DexField*)ptr;
		ptr += header.staticFieldsSize * sizeof(DexField);
	} else {
		class_data->staticFields = NULL;
	}

	if(header.instanceFieldsSize != 0) {
		class_data->instanceFields = (DexField*)ptr;
		ptr += header.instanceFieldsSize * sizeof(DexField);
	} else {
		class_data->instanceFields = NULL;
	}

	if(header.directMethodsSize != 0) {
		class_data->directMethods = (DexMethod*)ptr;
		ptr += header.directMethodsSize * sizeof(DexMethod);
	} else {
		class_data->directMethods = NULL;
	}

	if(header.virtualMethodsSize != 0) {
		class_data->virtualMethods = (DexMethod*)ptr;
	} else {
		class_data->virtualMethods = NULL;
	}

	int lastIndex = 0;
	DexField* fields = class_data->staticFields;
	for(int i = 0; i < header.staticFieldsSize; i++) {
		lastIndex += readUnsignedLeb128(&data);
		fields[i].accessFlags = readUnsignedLeb128(&data);
		fields[i].fieldIdx = lastIndex;
	}

	fields = class_data->instanceFields;
	lastIndex = 0;
	for(int i = 0; i < header.instanceFieldsSize; i++) {
		lastIndex += readUnsignedLeb128(&data);
		fields[i].accessFlags = readUnsignedLeb128(&data);
		fields[i].fieldIdx = lastIndex;
	}

	DexMethod* methods = class_data->directMethods;
	lastIndex = 0;
	for(int i = 0; i < header.directMethodsSize; i++) {
		lastIndex += readUnsignedLeb128(&data);
		methods[i].accessFlags = readUnsignedLeb128(&data);
		methods[i].codeOff = readUnsignedLeb128(&data);
		methods[i].methodIdx = lastIndex;
	}

	methods = class_data->virtualMethods;
	lastIndex = 0;
	for(int i = 0; i < header.virtualMethodsSize; i++) {
		lastIndex += readUnsignedLeb128(&data);
		methods[i].accessFlags = readUnsignedLeb128(&data);
		methods[i].codeOff = readUnsignedLeb128(&data);
		methods[i].methodIdx = lastIndex;
	}

	return class_data;
}

