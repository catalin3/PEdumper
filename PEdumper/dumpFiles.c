#include"dumpFiles.h"

void print_paths(PLIST_ENTRY head)
{
	LIST_ENTRY *le = head->Blink;
	int i = 0;
	while (le != head)
	{
		PATH_LE *pathEl = (PATH_LE*)CONTAINING_RECORD(le, PATH_LE, ListEntry);
		printf("PATH %d:\t %s\n", i, pathEl->value);
		PE_STATUS status;
		//status = create_file_mapping(pathEl->value);
		le = le->Blink;
		i++;
	}
}

HANDLE create_log_file(char *filePath)
{
	char fname[100];
	StringCchCopy(fname, MAX_PATH, filePath);
	int i;
	for (i = 0; i < MAX_PATH; i++)
	{
		if (fname[i] == '\\')
		{
			fname[i] = '_';
		}
	}
	StringCchCat(fname, MAX_PATH, ".log");
	//printf("\t\t LOG NAME %s\n\n", fname);
	SetCurrentDirectory("D:\\C\\Proiect\\Proiect\\Rezultate");
	HANDLE hfile = CreateFile(fname, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);

	return hfile;
}

PE_STATUS create_file_mapping(BYTE* filePath)
{	// Responsible for opening the file and creating a map of the file. It then calls p_dumpFile after validations pass.
	//printf("\n\n************************************************************\n%s\n************************************************************\n", filePath);
	HANDLE hFileMapping;
	LPVOID lpFileBase;

	printf("\t%s\n", filePath);
	HANDLE hFile = CreateFileA(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	int *fSize = NULL;
	DWORD sizeOfFile = GetFileSize(hFile, fSize);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		//printf("\tPROCESSOR: CreateFile failed (%d).\n", GetLastError());
		CloseHandle(hFile);
		return PE_STATUS_NOT_SUCCES_CREATE_FILE;
	}
	hFileMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
	if (hFileMapping == 0)
	{
		CloseHandle(hFile);
		//printf("\tPROCESSOR: CreateFileMapping failed (%d).\n", GetLastError());
		return PE_STATUS_NOT_SUCCES_CREATE_FILE_MAPPING;
	}

	HANDLE logFile = create_log_file(filePath);
	if (logFile == INVALID_HANDLE_VALUE)
	{
		CloseHandle(hFileMapping);
		CloseHandle(hFile);
		return PE_STATUS_NOT_SUCCES;
	}

	lpFileBase = MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
	if (lpFileBase == 0)
	{
		CloseHandle(hFileMapping);
		CloseHandle(hFile);
		CloseHandle(logFile);
		//printf("\tPROCESSOR: MapViewOfFile failed (%d).\n", GetLastError());
		return PE_STATUS_NOT_SUCCES;
	}

	PE_STATUS status = parcurgere_dumpFile(lpFileBase, sizeOfFile, logFile);

	UnmapViewOfFile(lpFileBase);
	CloseHandle(hFileMapping);
	CloseHandle(hFile);
	CloseHandle(logFile);
	return status;
}

PE_STATUS add_path_to_list(BYTE *path, PLIST_ENTRY head)
{
	PPATH_LE newEl = (PATH_LE*)malloc(sizeof(PATH_LE));
	newEl->value = (BYTE*)malloc(sizeof(BYTE)*MAX_PATH);
	strcpy_s(newEl->value, MAX_PATH, path);
	InsertHeadList(head, &newEl->ListEntry);
	return PE_STATUS_SUCCES;
}

void find_files(BYTE *bufferF, BYTE *file, PLIST_ENTRY head)
{
	WIN32_FIND_DATA ffd;
	HANDLE hFind = INVALID_HANDLE_VALUE;
	BYTE *szDirF = (BYTE*)malloc(sizeof(BYTE)*MAX_PATH);
	BYTE *pathF = (BYTE*)malloc(sizeof(BYTE)*MAX_PATH);


	StringCchCopy(szDirF, MAX_PATH, bufferF);
	StringCchCopy(pathF, MAX_PATH, bufferF);
	StringCchCat(pathF, MAX_PATH, "\\");
	StringCbCat(pathF, MAX_PATH, file);

	hFind = FindFirstFile(pathF, &ffd);


	if (INVALID_HANDLE_VALUE == hFind)
	{
		//printf(" Erroare in find_files %x\n", GetLastError());
		return 0;
	}

	do
	{
		StringCchCat(szDirF, MAX_PATH, "\\");
		StringCbCat(szDirF, MAX_PATH, ffd.cFileName);
		PE_STATUS status;
		//status = create_file_mapping(szDirF);
		//printf("%s\n", szDirF);
		if (!(ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
		{
			status = add_path_to_list(szDirF, head);
			validare(status);
		}
		StringCchCopy(szDirF, MAX_PATH, bufferF);
	} while (FindNextFile(hFind, &ffd) != 0);
	free(szDirF);
	free(pathF);
}


void find_directories(BYTE *buffer, BYTE *file, PLIST_ENTRY head)
{
	WIN32_FIND_DATA ffd;
	HANDLE hFind = INVALID_HANDLE_VALUE;
	BYTE *szDir = (BYTE*)malloc(sizeof(BYTE)*MAX_PATH);
	BYTE *path = (BYTE*)malloc(sizeof(BYTE)*MAX_PATH);

	StringCchCopy(szDir, MAX_PATH, buffer);
	StringCchCopy(path, MAX_PATH, szDir);
	StringCchCat(path, MAX_PATH, "\\");
	StringCchCat(szDir, MAX_PATH, "\\*");


	hFind = FindFirstFile(szDir, &ffd);

	if (INVALID_HANDLE_VALUE == hFind)
	{
		printf("Erroare in find_directories %x\n", GetLastError());
		return 0;
	}

	do
	{
		if (strcmp(ffd.cFileName, ".") == 0 || strcmp(ffd.cFileName, "..") == 0)
		{
			continue;
		}

		if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
		{
			StringCchCat(path, MAX_PATH, ffd.cFileName);

			BYTE *pathFile = (BYTE*)malloc(sizeof(BYTE)*MAX_PATH);
			StringCchCopy(pathFile, MAX_PATH, path);
			find_files(pathFile, file, head);
			free(pathFile);

			find_directories(path, file, head);
			StringCchCopy(path, MAX_PATH, buffer);
			StringCchCat(path, MAX_PATH, "\\");

		}

	} while (FindNextFile(hFind, &ffd) != 0);
	free(szDir);
	free(path);
}


DWORD WINAPI MyThreadFunction(LPVOID lpParam)
{
	PLIST_ENTRY head = (PLIST_ENTRY)lpParam;

	while (!InterlockedIsListEmpty(head, &criticalSection))
	{

		PLIST_ENTRY le = InterlockedRemoveHeadList(head, &criticalSection);
		//printf("Containing record\n");
		PATH_LE *pathEl = (PATH_LE*)CONTAINING_RECORD(le, PATH_LE, ListEntry);
		//printf("%d\n", GetCurrentThreadId());
		create_file_mapping(pathEl->value);
		//printf("\tFILE %s\n", pathEl->value);
	}

	Sleep(2000);

	ExitThread(0);
}

PE_STATUS scan_paths(int nrThreads, PLIST_ENTRY head)
{
	InitializeCriticalSection(&criticalSection);

	HANDLE *threads = (HANDLE)malloc(sizeof(HANDLE)*nrThreads);
	int i;
	for (i = 0; i < nrThreads; i++)
	{
		//printf("%d THREAD\n", i);
		threads[i] = CreateThread(NULL, 0, MyThreadFunction, (LPVOID)head, NULL, NULL);
	}

	WaitForMultipleObjects(nrThreads, threads, TRUE, INFINITE);

	DeleteCriticalSection(&criticalSection);
	free(threads);
	return PE_STATUS_NOT_SUCCES;
}


PE_STATUS get_args(char **argv, PLIST_ENTRY head)
{
	//SetCurrentDirectory("D:\\C\\Proiect\\Proiect\\fisiere_executabile");
	//SetCurrentDirectory("D:\\C\\Proiect\\Proiect\\fisiere_executabile\\crapa");
	//SetCurrentDirectory("C:\\Windows\\System32");
	//SetCurrentDirectory("D:\\C\\Proiect\\Proiect\\testbed");
	if (SetCurrentDirectory("D:\\C\\Proiect\\Proiect\\testbed") == 0)
	{
		return PE_STATUS_NOT_SUCCES;
	}
	PE_STATUS status;
	if (argv[1] == NULL)
	{
		return PE_STATUS_NOT_SUCCES;
	}
	else if (argv[2] == NULL)
	{
		status = create_file_mapping(argv[1]);
		add_path_to_list(argv[2], head);
	}
	else
	{
		int recursiv = 0;
		int nrThreaduri = 8;
		if (strchr(argv[2], 'r') || strchr(argv[2], 'R'))
		{
			printf("Recursiv\n");
			recursiv = 1;
			if (argv[3] != NULL)
			{
				nrThreaduri = atoi(argv[3]);
				printf("Threaduri %d\n", nrThreaduri);
			}
		}
		else
		{
			nrThreaduri = atoi(argv[2]);
			printf("Threaduri %d\n", nrThreaduri);
		}


		BYTE *buffer = (BYTE*)malloc(sizeof(BYTE) * MAX_PATH);
		buffer = _getcwd(NULL, 0);
		if (buffer == NULL)
		{
			printf("Error getcwd\n");
			return PE_STATUS_NOT_SUCCES;
		}
		else
		{
			//printf("Directorul curent: %s\n\n", buffer);
			BYTE *pathFile = (BYTE*)malloc(sizeof(BYTE)*MAX_PATH);
			StringCchCopy(pathFile, MAX_PATH, buffer);
			StringCchCat(pathFile, MAX_PATH, "\\");
			find_files(pathFile, argv[1], head);
			free(pathFile);
			find_directories(buffer, argv[1], head);

			//print_paths(head);
			printf("\n\n");
			//RemoveHeadList(head);
			scan_paths(nrThreaduri, head);
		}
		free(buffer);
	}

	return PE_STATUS_SUCCES;
}