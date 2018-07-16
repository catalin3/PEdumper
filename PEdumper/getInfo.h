#pragma once
#include<stdio.h>
#include<stdlib.h>
#include<direct.h>
#include<strsafe.h>
#include<windows.h>
#include<winnt.h>



typedef enum
{
	PE_STATUS_NOT_SUCCES,
	PE_STATUS_SUCCES,
	PE_STATUS_NOT_SUCCES_NOT_32,
	PE_STATUS_NOT_SUCCES_NOT_MZ,
	PE_STATUS_NOT_SUCCES_NOT_PE,
	PE_STATUS_NOT_SUCCES_CREATE_FILE,
	PE_STATUS_NOT_SUCCES_CREATE_FILE_MAPPING,
	PE_STATUS_NO_EXIST
}PE_STATUS;
