#include <stdio.h>
#include "DexFileParser.h"

int main(void)
{
	char* dex_path = "/Users/brian/Downloads/test/classes.dex";

	FILE* fp = fopen(dex_path, "r");
	if(fp == NULL) {
		printf("File %s open failed\n", dex_path);
		return -1;
	}

	fseek(fp, 0, SEEK_END);

	long file_len = ftell(fp);

	fseek(fp, 0, SEEK_SET);

	char* dex_cont = (char*)malloc(file_len);

	int ret = fread(dex_cont, 1, file_len, fp);
	if(ret < file_len) {
		printf("Read file %s ret %d\n", dex_path, ret);
	}

	DexFileParser* parser = new DexFileParser(dex_cont, file_len);

	parser->dexParseFile();



	fclose(fp);

	free(dex_cont);

	delete parser;

	return 0;
}
