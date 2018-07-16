#pragma once
#include<stdio.h>
#include<stdlib.h>
#include<direct.h>
#include<strsafe.h>
#include<windows.h>
#include<winnt.h>
#include"getInfo.h"
#include"list.h"	

CRITICAL_SECTION criticalSection;

typedef struct path_le
{
	char *value;
	LIST_ENTRY ListEntry;
} PATH_LE, *PPATH_LE;
