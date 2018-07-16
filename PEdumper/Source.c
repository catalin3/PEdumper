#include"Header.h"

CRITICAL_SECTION cs;

int main(int argc, char *argv[])
{
	InitializeCriticalSection(&cs);
	LIST_ENTRY head = { 0 };
	InitializeListHead(&head);

	PE_STATUS status = get_args(argv, &head);
	validare(status);

	//print_paths(&head);

	//scan_paths(8, &head);

	LIST_ENTRY *le = head.Blink;
	while (le != &head)
	{
		PATH_LE *pathEl = (PATH_LE*)CONTAINING_RECORD(le, PATH_LE, ListEntry);
		free(pathEl->value);
		le = le->Blink;
	}
	system("pause");
	DeleteCriticalSection(&cs);
	return 0;
}