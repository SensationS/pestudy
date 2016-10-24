#include <stdio.h>
#include <windows.h>
#include <winnt.h>
#include <time.h>

void PEParsingAndPrint(char* File_Path);

int main(int argc, char* argv[])
{
	if(argc !=2)
	{
		printf("Usage: $./peparser.exe [testsample.dll]\n");
		return 1;
	}

	PEParsingAndPrint(argv[1]);
	return 0;

}



void PEParsingAndPrint(char* File_Path)
{
	IMAGE_DOS_HEADER lpMapView_IDH;
	IMAGE_NT_HEADERS lpMapView_INH;
	PIMAGE_DOS_HEADER pIDH;
	PIMAGE_NT_HEADERS pINH;

	FILE* ifp;

	if((ifp = fopen(File_Path, "rb")) == NULL)
	{
		fprintf(stderr, "오류 : %s 파일을 열수 없습니다.\n", File_Path);
		exit(1);
	}

	// Start your Code
	
	// End Of Code

	printf("--------------- IMAGE_FILE_HEADERS ---------------\n");
	printf("Machine: %8p\n",pINH->FileHeader.Machine);
	printf("NumberOfSections: %8p\n",pINH->FileHeader.NumberOfSections);
	printf("TimeDateStamp: %8p\n",pINH->FileHeader.TimeDateStamp);
	printf("PointerToSymbolTable: %8p\n",pINH->FileHeader.PointerToSymbolTable);
	printf("NumberOfSymbols: %8p\n",pINH->FileHeader.NumberOfSymbols);
	printf("SizeOfOptionalHeader: %8p\n",pINH->FileHeader.SizeOfOptionalHeader);
	printf("Characteristics: %8p\n",pINH->FileHeader.Characteristics);
	printf("--------------- IMAGE_OPTIONAL_HEADER ---------------\n");
	printf("Magic:%8p\n",pINH->OptionalHeader.Magic);
	printf("MajorLinkerVersion:%8p\n",pINH->OptionalHeader.MajorLinkerVersion);
	printf("MinorLinkerVersion:%8p\n",pINH->OptionalHeader.MinorLinkerVersion);
	printf("SizeOfCode:%8p\n",pINH->OptionalHeader.SizeOfCode);
	printf("SizeOfInitializedData:%8p\n",pINH->OptionalHeader.SizeOfInitializedData);
	printf("SizeOfUninitializedData:%8p\n",pINH->OptionalHeader.SizeOfUninitializedData);
	printf("AddressOfEntryPoint:%8p\n",pINH->OptionalHeader.AddressOfEntryPoint);
	printf("BaseOfCode:%8p\n",pINH->OptionalHeader.BaseOfCode);
	//printf("BaseOfData:%p\n",pINH->OptionalHeader.BaseOfData);
	printf("ImageBase:%8p\n",pINH->OptionalHeader.ImageBase);
	printf("SectionAlignment:%8p\n",pINH->OptionalHeader.SectionAlignment);
	printf("FileAlignment:%8p\n",pINH->OptionalHeader.FileAlignment);
	printf("MajorOperatingSystemVersion:%8p\n",pINH->OptionalHeader.MajorOperatingSystemVersion);
	printf("MinorOperatingSystemVersion:%8p\n",pINH->OptionalHeader.MinorOperatingSystemVersion);
	printf("MajorImageVersion:%8p\n",pINH->OptionalHeader.MajorImageVersion);
	printf("MinorImageVersion:%8p\n",pINH->OptionalHeader.MinorImageVersion);
	printf("MajorSubsystemVersion:%8p\n",pINH->OptionalHeader.MajorSubsystemVersion);
	printf("MinorSubsystemVersion:%8p\n",pINH->OptionalHeader.MinorSubsystemVersion);
	printf("Win32VersionValue:%8p\n",pINH->OptionalHeader.Win32VersionValue);
	printf("SizeOfImage:%8p\n",pINH->OptionalHeader.SizeOfImage);
	printf("SizeOfHeaders:%8p\n",pINH->OptionalHeader.SizeOfHeaders);
	printf("CheckSum:%8p\n",pINH->OptionalHeader.CheckSum);
	printf("Subsystem:%8p\n",pINH->OptionalHeader.Subsystem);
	printf("DllCharacteristics:%8p\n",pINH->OptionalHeader.DllCharacteristics);
	printf("SizeOfStackReserve:%8p\n",pINH->OptionalHeader.SizeOfStackReserve);
	printf("SizeOfStackCommit:%8p\n",pINH->OptionalHeader.SizeOfStackCommit);
	printf("SizeOfHeapReserve:%8p\n",pINH->OptionalHeader.SizeOfHeapReserve);
	printf("SizeOfHeapCommit:%8p\n",pINH->OptionalHeader.SizeOfHeapCommit);
	printf("LoaderFlags:%8p\n",pINH->OptionalHeader.LoaderFlags);
	printf("NumberOfRvaAndSizes:%8p\n",pINH->OptionalHeader.NumberOfRvaAndSizes);

	fclose(ifp);
}

