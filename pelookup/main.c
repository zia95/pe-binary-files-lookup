#include<stdio.h>
#include"pelookup.h"

#define DB_FILE "C:/Users/ziaud/Desktop/ofiles/odbg1.1.0/OLLYDBG.EXE"
int main(int argc, char** argv) 
{
	LPVOID lpPeData = pe_file_open(DB_FILE);
	if (lpPeData)
	{
		//hex_dump((char*)g_lpFile, (char*)g_lpFile+1000);

		PIMAGE_DOS_HEADER pDosHdr = print_dos_header(lpPeData);
		if (pDosHdr)
		{
			PIMAGE_NT_HEADERS32	pNtHdr = print_nt_header32(pDosHdr, true, true);
			if (pNtHdr)
			{
				print_sections32(pNtHdr, true);
			}
			else
			{
				perror("ERROR: File is not a valid PE file.\n");
			}
		}
		else
		{
			perror("ERROR: File is not a valid DOS file.\n");
		}

		pe_file_close();
	}
	else
	{
		perror("ERROR: Failed to open the file specified.\n");
	}
}