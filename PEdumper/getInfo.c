#include"getInfo.h"

DWORD convertRVA(DWORD rva, PIMAGE_SECTION_HEADER FirstSectionHeader, PIMAGE_FILE_HEADER PEFileImageHeader)
{
	int j = 0;
	PIMAGE_SECTION_HEADER i = FirstSectionHeader;

	for (; j < PEFileImageHeader->NumberOfSections; i++, j++)
	{
		if (rva >= i->VirtualAddress && rva < i->VirtualAddress + i->Misc.VirtualSize)
		{
			break;
		}
	}
	if (j >= PEFileImageHeader)
	{
		return -1;
	}
	return rva + i->PointerToRawData - i->VirtualAddress;
}

PE_STATUS validare_adresa(DWORD adr)
{
	return PE_STATUS_SUCCES;
}

PE_STATUS dumpExportSection(HANDLE lpFileBase, PIMAGE_SECTION_HEADER pImageSectionHeader, PIMAGE_FILE_HEADER pImageFileHeader, PIMAGE_DOS_HEADER pImageDosHeader, PIMAGE_OPTIONAL_HEADER pImageOptionalHeader, int sizeOfFile, HANDLE logFile)
{
	BYTE buffer[1000];
	SIZE_T sz;

	IMAGE_DATA_DIRECTORY iDirectoryEntryEport = pImageOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];		//EXPORTURI

	DWORD virtualAddress = iDirectoryEntryEport.VirtualAddress;
	//printf("DataDirectoryExports %xh\n\n", iDirectoryEntryEport.VirtualAddress);
	memset(buffer, 0, 1000);
	sprintf_s(buffer, 1000, "VirtualAddress\t0x%x\r\n", (ULONG)virtualAddress);
	sz = strlen(buffer);
	WriteFile(logFile, buffer, sz, NULL, NULL);

	if (iDirectoryEntryEport.VirtualAddress == 0)
	{
		//printf("IMAGE_DIRECTORY_ENTRY_EXPORT.VirtualAddress = 0\n\n");
		return PE_STATUS_NOT_SUCCES;
	}
	PIMAGE_EXPORT_DIRECTORY ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((DWORD)pImageDosHeader + convertRVA(iDirectoryEntryEport.VirtualAddress, pImageSectionHeader, pImageFileHeader));
	if (ExportDirectory >= sizeOfFile + (DWORD)lpFileBase)
	{
		return PE_STATUS_NOT_SUCCES;
	}

	DWORD numberOfFunctions = ExportDirectory->NumberOfFunctions;
	//printf("numberOfFunctions %d\n\n", numberOfFunctions);
	memset(buffer, 0, 1000);
	sprintf_s(buffer, 1000, "NumberOfFunctions\t0x%x\r\n", (ULONG)numberOfFunctions);
	sz = strlen(buffer);
	WriteFile(logFile, buffer, sz, NULL, NULL);

	DWORD numberOfNames = ExportDirectory->NumberOfNames;
	//printf("numberOfnames %d\n\n", ExportDirectory->NumberOfNames);
	memset(buffer, 0, 1000);
	sprintf_s(buffer, 1000, "NumberOfNames\t0x%x\r\n", (ULONG)numberOfNames);
	sz = strlen(buffer);
	WriteFile(logFile, buffer, sz, NULL, NULL);
	//if (numberOfFunctions < ExportDirectory->NumberOfNames)
	//{
	//	return PE_STATUS_NOT_SUCCES;
	//}

	DWORD base = ExportDirectory->Base;
	//printf("exportDirectoryBase %d\n\n", base);
	memset(buffer, 0, 1000);
	sprintf_s(buffer, 1000, "ExportDirectoryBase\t0x%x\r\n", (ULONG)base);
	sz = strlen(buffer);
	WriteFile(logFile, buffer, sz, NULL, NULL);

	if (numberOfFunctions > 0)
	{
		memset(buffer, 0, 1000);
		sprintf_s(buffer, 1000, "FUNCTII EXPORTATE\r\n");
		sz = strlen(buffer);
		WriteFile(logFile, buffer, sz, NULL, NULL);
		PDWORD ExportedFunctions = (PDWORD)((DWORD)pImageDosHeader + convertRVA(ExportDirectory->AddressOfNames, pImageSectionHeader, pImageFileHeader));
		PDWORD AddressOfFunctions = (PDWORD)((DWORD)pImageDosHeader + convertRVA(ExportDirectory->AddressOfFunctions, pImageSectionHeader, pImageFileHeader));
		PWORD AddressOfNamesOrdinals = (PWORD)((DWORD)pImageDosHeader + convertRVA(ExportDirectory->AddressOfNameOrdinals, pImageSectionHeader, pImageFileHeader));

		for (int i = 0; i<ExportDirectory->NumberOfNames; i++)
		{

			DWORD functionAddress = AddressOfFunctions[i];
			DWORD conv = convertRVA((DWORD)ExportedFunctions[AddressOfNamesOrdinals[i]], pImageSectionHeader, pImageFileHeader);
			if (conv <= sizeOfFile && conv>pImageOptionalHeader->SizeOfHeaders)
			{
				DWORD expFAO = (DWORD)ExportedFunctions[AddressOfNamesOrdinals[i]];
				DWORD conv = convertRVA((DWORD)ExportedFunctions[AddressOfNamesOrdinals[i]], pImageSectionHeader, pImageFileHeader);
				if (conv != -1)
				{
					if (functionAddress < sizeOfFile + (DWORD)lpFileBase)
					{
						BYTE buff[500000];
						LPSTR functionName = (PCHAR)((DWORD)pImageDosHeader + conv);
						//system("pause");
						//printf("Name    %s\nAddress %xh\nOrdinal %x\n\n", functionName, functionAddress, AddressOfNamesOrdinals[i]);

						memset(buff, 0, 500000);
						if (sprintf_s(buff, 500000, "Name: %s\r\n", (ULONG)functionName) != -1)
						{
							sz = strlen(buff);
							WriteFile(logFile, buff, sz, NULL, NULL);
						}


						memset(buffer, 0, 1000);
						sprintf_s(buffer, 1000, "Address: 0x%x\r\n", (ULONG)functionAddress);
						sz = strlen(buffer);
						WriteFile(logFile, buffer, sz, NULL, NULL);
						memset(buffer, 0, 1000);
						sprintf_s(buffer, 1000, "Ordinal: %x\r\n\r\n", (ULONG)AddressOfNamesOrdinals[i]);
						sz = strlen(buffer);
						WriteFile(logFile, buffer, sz, NULL, NULL);
					}
				}
			}
		}
	}
	else
	{
		//printf("Nu exista functii exportate!\n");
	}
	return PE_STATUS_SUCCES;
}

int validareThunk(PIMAGE_THUNK_DATA pImageThunkData)
{
	if (pImageThunkData->u1.Ordinal == 0)
	{
		return 0;
	}
	return 1;
}

int validarePIMAGE_IMPORT_DESCRIPTOR(PIMAGE_IMPORT_DESCRIPTOR pImageImportDescriptor)
{
	if (pImageImportDescriptor->Characteristics == 0 && pImageImportDescriptor->OriginalFirstThunk == 0 && pImageImportDescriptor->FirstThunk == 0 && pImageImportDescriptor->ForwarderChain == 0 && pImageImportDescriptor->Name == 0 && pImageImportDescriptor->TimeDateStamp == 0)
	{
		return 0;
	}
	return 1;
}

PE_STATUS dumpImportSection(HANDLE lpFileBase, PIMAGE_SECTION_HEADER pImageSectionHeader, PIMAGE_FILE_HEADER pImageFileHeader, PIMAGE_DOS_HEADER pImageDosHeader, PIMAGE_OPTIONAL_HEADER pImageOptionalHeader, int sizeOfFile, HANDLE logFile)
{
	BYTE buffer[200];
	SIZE_T sz;

	IMAGE_DATA_DIRECTORY iDirectoryEntryImport = pImageOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];		//IMPORTURI
	DWORD VirtualAddress = iDirectoryEntryImport.VirtualAddress;
	//printf("IMAGE_DIRECTORY_ENTRY_IMPORT.VirtualAddress %xh\n\n", iDirectoryEntryImport.VirtualAddress);
	memset(buffer, 0, 200);
	sprintf_s(buffer, 200, "virtualAddress\t0x%x\r\n", (ULONG)VirtualAddress);
	sz = strlen(buffer);
	WriteFile(logFile, buffer, sz, NULL, NULL);

	DWORD size = iDirectoryEntryImport.Size;
	//printf("IMAGE_DIRECTORY_ENTRY_IMPORT.Size %x\n\n", iDirectoryEntryImport.Size);
	memset(buffer, 0, 200);
	sprintf_s(buffer, 200, "size\t0x%x\r\n", (ULONG)size);
	sz = strlen(buffer);
	WriteFile(logFile, buffer, sz, NULL, NULL);
	if (iDirectoryEntryImport.Size == 0 || iDirectoryEntryImport.Size >= sizeOfFile + (DWORD)lpFileBase)
	{
		return PE_STATUS_NOT_SUCCES;
	}

	PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)pImageDosHeader + convertRVA(iDirectoryEntryImport.VirtualAddress, pImageSectionHeader, pImageFileHeader));
	//printf("\tFUNCTII IMPORTATE:\n");
	memset(buffer, 0, 200);
	sprintf_s(buffer, 200, "\tFUNCTII IMPORTATE:\r\n");
	sz = strlen(buffer);
	WriteFile(logFile, buffer, sz, NULL, NULL);
	if (ImportDescriptor >= sizeOfFile + (DWORD)lpFileBase)
	{
		return PE_STATUS_NOT_SUCCES;
	}

	while (validarePIMAGE_IMPORT_DESCRIPTOR(ImportDescriptor))
	{
		if (ImportDescriptor->Name >= sizeOfFile + (DWORD)lpFileBase)
		{
			return PE_STATUS_NOT_SUCCES;
		}
		DWORD name = (DWORD)((DWORD)pImageDosHeader + convertRVA(ImportDescriptor->Name, pImageSectionHeader, pImageFileHeader));
		if (name >= sizeOfFile + (DWORD)lpFileBase)
		{
			return PE_STATUS_NOT_SUCCES;
		}
		//printf("\n%s\n", name);
		memset(buffer, 0, 200);
		sprintf_s(buffer, 200, "\r\n%s\r\n", (ULONG)name);
		sz = strlen(buffer);
		WriteFile(logFile, buffer, sz, NULL, NULL);
		PIMAGE_THUNK_DATA pImageThunkData = ImportDescriptor->OriginalFirstThunk;
		//printf("OriginalFirstThunkRVA: %d\n", pImageThunkData);
		if (pImageThunkData >= sizeOfFile + (DWORD)lpFileBase)
		{
			return PE_STATUS_NOT_SUCCES;
		}

		if (pImageThunkData == NULL)
		{
			pImageThunkData = ImportDescriptor->FirstThunk;
			//printf("FirstThunkRVA: %d\n", pImageThunkData);
			if (pImageThunkData >= sizeOfFile + (DWORD)lpFileBase)
			{
				return PE_STATUS_NOT_SUCCES;
			}
		}


		pImageThunkData = (PIMAGE_THUNK_DATA)((DWORD)pImageDosHeader + convertRVA(pImageThunkData, pImageSectionHeader, pImageFileHeader));
		if (pImageThunkData >= sizeOfFile + (DWORD)lpFileBase)
		{
			return PE_STATUS_NOT_SUCCES;
		}
		//printf("FirstThunkVA: %d\n", pImageThunkData);

		if (ImportDescriptor->TimeDateStamp == 0 && ImportDescriptor->Name == 0)
		{
			//printf("Empty IMAGE_IMPORT_DESCRIPTOR\n");
			return PE_STATUS_NOT_SUCCES;
		}
		//printf("ImportDescriptor->TimeDateStamp %x\n", ImportDescriptor->TimeDateStamp);

		while (validareThunk(pImageThunkData) != 0)
		{
			DWORD ordinal = pImageThunkData->u1.Ordinal;
			if (ordinal & IMAGE_ORDINAL_FLAG)
			{
				//printf("\tOrdinal %xh\n", ordinal);
				memset(buffer, 0, 200);
				sprintf_s(buffer, 200, "\r\tOrdinal %xh\r\n", (ULONG)ordinal);
				sz = strlen(buffer);
				WriteFile(logFile, buffer, sz, NULL, NULL);
			}
			else
			{
				PIMAGE_IMPORT_BY_NAME pImageImportByName = pImageThunkData->u1.AddressOfData;

				if (pImageImportByName >= sizeOfFile + (DWORD)lpFileBase)
				{
					return PE_STATUS_NOT_SUCCES;
				}
				pImageImportByName = (PIMAGE_IMPORT_BY_NAME)((DWORD)pImageDosHeader + convertRVA(pImageImportByName, pImageSectionHeader, pImageFileHeader));

				BYTE buff[500000];
				//printf("\t%s \n", pImageImportByName->Name);

				memset(buff, 0, 500000);
				sprintf_s(buff, 500000, "\r\t%sh\r\n", (ULONG)pImageImportByName->Name);
				sz = strlen(buffer);
				WriteFile(logFile, buff, sz, NULL, NULL);
			}
			pImageThunkData++;
		}
		if (ImportDescriptor >= sizeOfFile + (DWORD)lpFileBase)
		{
			return PE_STATUS_NOT_SUCCES;
		}
		ImportDescriptor++;
	}
	return PE_STATUS_SUCCES;
}

PE_STATUS parcurgere_dumpFile(HANDLE lpFileBase, int sizeOfFile, HANDLE logFile)
{
	BYTE buffer[200];
	SIZE_T sz;

	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)lpFileBase;
	//printf("IMAGE_DOS_HEADER %xh\n\n", pImageDosHeader);
	memset(buffer, 0, 200);
	sprintf_s(buffer, 200, "pImageDosHeader\t0x%x\r\n", (ULONG)pImageDosHeader);
	sz = strlen(buffer);
	WriteFile(logFile, buffer, sz, NULL, NULL);

	if (pImageDosHeader >= sizeOfFile + (DWORD)lpFileBase)
	{
		return PE_STATUS_NOT_SUCCES;
	}

	//if (pImageDosHeader->e_magic != 23117 && pImageDosHeader->e_magic != 17220)	// MZ -> 23117
	WORD e_magic = pImageDosHeader->e_magic;
	//printf("e_magic %xh\n\n", pImageDosHeader->e_magic);

	memset(buffer, 0, 200);
	sprintf_s(buffer, 200, "e_magic\t0x%x\r\n", (ULONG)e_magic);
	sz = strlen(buffer);

	if (WriteFile(logFile, &buffer, (DWORD)sz, NULL, NULL) == 0)
	{
		return PE_STATUS_NOT_SUCCES;
	}

	if (pImageDosHeader->e_magic != 23117)
	{
		return PE_STATUS_NOT_SUCCES_NOT_MZ;
	}

	DWORD e_lfanew = pImageDosHeader->e_lfanew;
	if (e_lfanew >= sizeOfFile + (DWORD)lpFileBase)
	{
		return PE_STATUS_NOT_SUCCES;
	}
	memset(buffer, 0, 200);
	sprintf_s(buffer, 200, "e_lfanew\t0x%x\r\n", (ULONG)e_lfanew);
	sz = strlen(buffer);
	WriteFile(logFile, buffer, sz, NULL, NULL);

	PIMAGE_NT_HEADERS pImageNtHeaders = (PIMAGE_NT_HEADERS)((DWORD)lpFileBase + pImageDosHeader->e_lfanew);
	if (pImageNtHeaders >= sizeOfFile + (DWORD)lpFileBase)
	{
		return PE_STATUS_NOT_SUCCES;
	}
	PIMAGE_FILE_HEADER pImageFileHeader = (PIMAGE_OPTIONAL_HEADER)&(pImageNtHeaders->FileHeader);

	DWORD Signature = pImageNtHeaders->Signature;
	if (Signature != 17744)	//4550h -> PE
	{
		return PE_STATUS_NOT_SUCCES_NOT_PE;
	}
	//printf("signature %xh\n\n", pImageNtHeaders->Signature);
	memset(buffer, 0, 200);
	sprintf_s(buffer, 200, "Signature\t0x%x\r\n", (ULONG)Signature);
	sz = strlen(buffer);
	WriteFile(logFile, buffer, sz, NULL, NULL);

	//printf("machine %xh\n\n", pImageFileHeader->Machine);
	WORD machine = pImageFileHeader->Machine;
	if (machine != 332)	//32 bit
	{
		return PE_STATUS_NOT_SUCCES_NOT_32;
	}
	memset(buffer, 0, 200);
	sprintf_s(buffer, 200, "machine\t0x%x\r\n", (ULONG)machine);
	sz = strlen(buffer);
	WriteFile(logFile, buffer, sz, NULL, NULL);

	WORD numberOfSections = pImageFileHeader->NumberOfSections;
	//printf("NumberOfSections %xh\n\n", numberOfSections);
	memset(buffer, 0, 200);
	sprintf_s(buffer, 200, "NumberOfSections\t0x%x\r\n", (ULONG)numberOfSections);
	sz = strlen(buffer);
	WriteFile(logFile, buffer, sz, NULL, NULL);

	PIMAGE_OPTIONAL_HEADER pImageOptionalHeader = (PIMAGE_OPTIONAL_HEADER)&(pImageNtHeaders->OptionalHeader);

	//printf("PIMAGE_OPTIONAL_HEADER %xh\n\n", pImageOptionalHeader);
	if (pImageOptionalHeader >= sizeOfFile + (DWORD)lpFileBase)
	{
		return PE_STATUS_NOT_SUCCES;
	}

	WORD sizeOfOptionalHeader = pImageFileHeader->SizeOfOptionalHeader;
	//printf("SizeOfOptionalHeader %xh\n\n", sizeOfOptionalHeader);
	memset(buffer, 0, 200);
	sprintf_s(buffer, 200, "SizeOfOptionalHeader\t0x%x\r\n", (ULONG)sizeOfOptionalHeader);
	sz = strlen(buffer);
	WriteFile(logFile, buffer, sz, NULL, NULL);

	DWORD ImageBase = pImageOptionalHeader->ImageBase;
	//printf("ImageBase %xh\n\n", ImageBase);
	memset(buffer, 0, 200);
	sprintf_s(buffer, 200, "ImageBase\t0x%x\r\n", (ULONG)ImageBase);
	sz = strlen(buffer);
	WriteFile(logFile, buffer, sz, NULL, NULL);

	DWORD sizeOfImage = pImageOptionalHeader->SizeOfImage;
	//printf("SizeOfImage %xh\n\n", sizeOfImage);
	memset(buffer, 0, 200);
	sprintf_s(buffer, 200, "SizeOfImage\t0x%x\r\n", (ULONG)sizeOfImage);
	sz = strlen(buffer);
	WriteFile(logFile, buffer, sz, NULL, NULL);

	//PIMAGE_SECTION_HEADER pImageSectionHeader = (DWORD)pImageNtHeaders + 24 + pImageFileHeader->SizeOfOptionalHeader;
	//PIMAGE_SECTION_HEADER pImageSectionHeader =  (BYTE*) pImageNtHeaders + sizeof(pImageNtHeaders.Signature) + sizeof(pImageNtHeaders.FileHeader) + pImageNtHeaders.FileHeader.SizeOfOptionalHeader
	PIMAGE_SECTION_HEADER pImageSectionHeader = IMAGE_FIRST_SECTION(pImageNtHeaders);
	//PIMAGE_SECTION_HEADER pImageSectionHeader = ((PIMAGE_SECTION_HEADER)((ULONG_PTR)(pImageNtHeaders)+FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader) + pImageFileHeader->SizeOfOptionalHeader));

	//printf("PIMAGE_SECTION_HEADER %xh\n\n", pImageSectionHeader);
	if (pImageSectionHeader >= sizeOfFile + (DWORD)lpFileBase)
	{
		return PE_STATUS_NOT_SUCCES;
	}

	memset(buffer, 0, 200);
	sprintf_s(buffer, 200, "%s", (ULONG)pImageSectionHeader->Name);
	if (strcmp(buffer, ".Adson") != 0)
	{
		printf("Section name: %s\n\n", pImageSectionHeader->Name);
	}

	memset(buffer, 0, 200);
	sprintf_s(buffer, 200, "FileSize\t0x%x\r\n", (ULONG)sizeOfFile);
	sz = strlen(buffer);
	WriteFile(logFile, buffer, sz, NULL, NULL);


	PE_STATUS status = dumpExportSection(lpFileBase, pImageSectionHeader, pImageFileHeader, pImageDosHeader, pImageOptionalHeader, sizeOfFile, logFile);

	status = dumpImportSection(lpFileBase, pImageSectionHeader, pImageFileHeader, pImageDosHeader, pImageOptionalHeader, sizeOfFile, logFile);

	return status;
}