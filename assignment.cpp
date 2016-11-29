//Visual Studio 2012 Professional 환경에서 코딩
///시그니쳐 검색 알고리즘으로는 보이어 무어 알고리즘을 사용

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <Windows.h>
#include <WinNT.h>
#include <io.h>
#pragma warning (disable: 4996) // 파일 입출력, 입출력 함수등의 함수경고 무시
#pragma warning (disable: 4244) //형변환 경고 무시

typedef struct Signature
{
	unsigned char arr[12];
}Sig;	//signature 단위로 끊을 구조체

bool findSignature(unsigned char* str);
void PEparsingAndPrint(char* File_Path, unsigned int offset);
void FileInput(char* FileName);
char* TimeDateStampToString(DWORD sec);
/* 여기까지 PE파일이랑 관련 함수 선언 */

void preBmBc(unsigned char *x, int m, int bmBc[]);
void BM(unsigned char *x, int m,unsigned char *y, int n);

#define MAX(a,b)   (((a)>(b))?(a):(b)) //a와 b를 비교하여 a값이 크면 a를 실행하고 b값이 크면 b를 실행(3항연산자)
#define ASIZE    256                   
#define XSIZE    256
#define buff_size 4096
#define sig_size 4
/* 보이어 무어 알고리즘 함수 선언 */
unsigned long offset;

int main(int argc, char **argv)
{
	char File_Path[MAX_PATH], File_Name[MAX_PATH];
	clock_t start, end;
	start = clock();
	
	if(argc !=2)
	{
		printf("사용법 : 실행파일 이름 [진단대상 폴더]\n");
		printf("EX : 20072324_박용준.exe c:\\테스트폴더\n");
		printf("폴더 명에 띄어쓰기가 되어있는지도 확인해주세요. 있으면 띄어쓰기를 제거해주세요\n");
		system("PAUSE");
		exit(1);
	}
	strcpy(File_Path, argv[1]); 
	printf("악성파일 검색대상 폴더경로: %s\n\n", File_Path);

	strcat(File_Path, "\\*.*");	//폴더 내 파일 전체를 찾는다.

	struct _finddata_t stFI;
	int flag;

	if ( (flag = _findfirst(File_Path, &stFI)) == -1 )
	{
		printf("[그러한 폴더가 없거나 폴더내에 파일이 없습니다.]\n");
		_findclose(flag);
		exit(1);
	}
	else
	{
		do{
			if ((strcmp(stFI.name, ".") == 0 || strcmp(stFI.name, "..") == 0))
				continue;
			strcpy(File_Name, argv[1]), strcat(File_Name, "\\"), strcat(File_Name, stFI.name);
			FileInput(File_Name);
		}while( _findnext(flag, &stFI ) == 0 );
	}
	_findclose(flag);
	end = clock();
	printf("소요시간 : %f\n", (double)(end - start) / CLK_TCK);
	system("PAUSE");
	return 0;
}

/* 입력 된 파일들을 실질적으로 처리해주는 함수 */
void FileInput(char* FileName)
{
	unsigned char File_arr[12] ={0x00,};
	unsigned char c;
	bool isMalcious = false;
	unsigned char x[sig_size] = {0x5F, 0x21, 0xCA, 0xFE};
	unsigned char buff[buff_size];

	FILE* ifp;

	if((ifp = fopen(FileName, "rb")) == NULL)
	{
		fprintf(stderr, "오류 : %s 파일을 열수 없습니다.\n", FileName);
		exit(1);
	}

	fseek(ifp, 0,SEEK_SET);

	unsigned long cnt=0;	//몇 번째 읽는 것인지 저장하는 변수
	int check;
	offset = 0;
	while(check = fread(&buff, sizeof(unsigned char) * buff_size,1, ifp))
	{
		BM(x, sig_size, buff,buff_size); // {0x5F, 0x21, 0xCA, 0xFE} 부분 보이어무어 알고리즘으로 먼저 찾음

		if(check == 1 && offset != 0)
		{
			fseek(ifp, cnt*buff_size+offset-(cnt*sig_size), SEEK_SET);
			fread(File_arr, sizeof(unsigned char) *12, 1, ifp);

			if(isMalcious = findSignature(File_arr))	//나머지 부분 악성 시그니쳐 여부 확인. 맞으면 true 리턴하고 break
			{	
				offset =  cnt*buff_size+offset-(cnt*sig_size);
				break;
			}
			else
			{
				fseek(ifp, cnt*buff_size+offset-(cnt*sig_size), SEEK_SET);
				continue;	//나머지부분이 악성 시그니쳐가 아니면 다시 계속 수행 할것임.
			}
		}
		fseek(ifp, -sig_size, SEEK_CUR);	//파일 포인터 4byte 시프트.
		cnt++;
	}

	if(check == 0)	//파일이 4k보다 작거나 4k보다 안남았을때는 순차 검색
	{
		fseek(ifp, cnt*buff_size+offset-(cnt*sig_size), SEEK_SET);
		for(int i=0; i <12; i++){
			fread(&c, sizeof(unsigned char), 1, ifp);
			File_arr[i++] = c;
		}	// 처음 12개를 읽고,,,

		while(check = fread(&c, sizeof(unsigned char), 1, ifp))	// 하나씩 옮겨가면서 검사
		{
			memcpy(File_arr,File_arr+1, sizeof(Sig)-1);	//배열 이동 한칸씩 shift
			File_arr[sizeof(Sig)-1] = c; //맨마지막 배열(12번째)에 새로 읽은거 집어넣기.

			if(isMalcious = findSignature(File_arr))	//악성 시그니쳐 여부 확인. 맞으면 true 리턴하고 break
				break;
		}
		if(isMalcious == true)
		{
			offset =  ftell(ifp)-12;	//파일 포인터가 12번째로 지나가 있기때문에 -12 해준다.
		}
	}

	if(isMalcious == true)
		PEparsingAndPrint(FileName, offset);	//나머지 PE파싱 하고, 필요한 부분 출력
	offset = 0;
	fclose(ifp);
}

/* 12byte 시그니쳐가 맞는지 확인해주는 함수 */
bool findSignature(unsigned char* str)
{
	Sig s = {0x5F, 0x21, 0xCA, 0xFE, (0x00), 0xBE, 0xDE, 0xAD, 0xC0, (0x00), 0x21, 0x5F}; 
	// 찾을 시그니쳐, 괄호친거는 don't-care

	for(int i=0; i < 12; i++)
	{
		if(i == sig_size || i == 9) continue; // don't-care에서는 continue함.		
		if(s.arr[i] != str[i])
			return false;
	}
	return true;
}

/* PE파일을 파싱하고 필요한 부분을 출력해주는 함수 */
void PEparsingAndPrint(char* File_Path, unsigned int File_offset)
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

	fread(&lpMapView_IDH, sizeof(IMAGE_DOS_HEADER), 1, ifp);
	pIDH = &lpMapView_IDH;	//DOS헤더 끊고 포인트

	fseek(ifp, pIDH->e_lfanew,SEEK_SET);
	fread(&lpMapView_INH, sizeof(IMAGE_NT_HEADERS), 1, ifp);
	pINH = &lpMapView_INH;	//NT헤더 끊고 포인트

	PIMAGE_SECTION_HEADER pSH = NULL;
	IMAGE_SECTION_HEADER lpMapView_ISH;
	DWORD pOptionalHeader;
	pOptionalHeader = pIDH->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);	//Optional Header 위치 잡아줌.
	for(DWORD j=0; j < pINH->FileHeader.NumberOfSections; j++)
	{
		pSH = (PIMAGE_SECTION_HEADER)(pOptionalHeader + pINH->FileHeader.SizeOfOptionalHeader + IMAGE_SIZEOF_SECTION_HEADER *j);
		fseek(ifp,(long)pSH, SEEK_SET);
		fread(&lpMapView_ISH,sizeof(IMAGE_SECTION_HEADER), 1, ifp);
		pSH = &lpMapView_ISH;
		if(pSH->PointerToRawData > File_offset)		
		{
			j--;
			pSH = (PIMAGE_SECTION_HEADER)(pOptionalHeader + pINH->FileHeader.SizeOfOptionalHeader + IMAGE_SIZEOF_SECTION_HEADER *j);
			fseek(ifp,(long)pSH, SEEK_SET);
			fread(&lpMapView_ISH,sizeof(IMAGE_SECTION_HEADER), 1, ifp);
			pSH = &lpMapView_ISH;
			break;
		}
	}
	

	printf("%s - 악성\n", File_Path);
	printf("%s","EP : "); 
	unsigned char  s[32];
	unsigned char c;

	PIMAGE_SECTION_HEADER pfirst_SH = NULL;
	IMAGE_SECTION_HEADER lpMapView_fISH;
	pfirst_SH = (PIMAGE_SECTION_HEADER)(pOptionalHeader + pINH->FileHeader.SizeOfOptionalHeader);
	fseek(ifp,(long)pfirst_SH, SEEK_SET);
	fread(&lpMapView_fISH,sizeof(IMAGE_SECTION_HEADER), 1, ifp);
	pfirst_SH = &lpMapView_fISH;
	fseek(ifp, pINH->OptionalHeader.AddressOfEntryPoint -  pfirst_SH->VirtualAddress + pfirst_SH ->PointerToRawData , SEEK_SET);
	//시작 EP는 AddressOfEntryPoint - 첫번? 섹션 rva + 첫번째 섹션 PointerToRawData

	for(int i=0; i < 32; i++)
	{
		fread(&c, sizeof(unsigned char), 1, ifp);
		s[i] = c;	
		printf(" %X", s[i]); //엔트리포인트 32자리 출력
	}

	printf("\nFile Offset : 0x%0X", File_offset);	//파일 오프셋 출력
	unsigned int RVA;
	printf(", RVA : 0x%0X\n", RVA = File_offset + pINH->OptionalHeader.ImageBase - pSH->PointerToRawData + pSH->VirtualAddress);
	//시그니쳐가 메모리에 올라가는 RVA = RAW +ImageBase + VirtualAddress - PointerToRawData
	printf("Number of Sections: %d, Time Stamp : %s\n\n", 
		pINH->FileHeader.NumberOfSections, TimeDateStampToString(pINH->FileHeader.TimeDateStamp));

	fclose(ifp);
}

/* TimeDateStamp값을 적절하게 바꿔주는 함수 */
char* TimeDateStampToString(DWORD sec)
{
	char * str = (char *)malloc(100);

	time_t t = (time_t)sec;
	struct tm * ptime=localtime(&t);

	sprintf(str, "%d/%d/%d", ptime->tm_year+1900,ptime->tm_mon+1, ptime->tm_mday);

	return str;
}

/*             검색알고리즘                         */
/*----- 이하 보이어 무어 알고리즘 함수들 ----- */
void preBmBc(unsigned char *x, int m, int bmBc[])
{
	int i; //i 변수 선언
	for (i = 0; i < ASIZE; ++i)
		bmBc[i] = m;
	for (i = 0; i < m - 1; ++i)
		bmBc[x[i]] = m - i - 1; 
}

void suffixes(unsigned char *x, int m, int *suff) 
{
	int f, g, i;
	suff[m - 1] = m;
	g = m - 1;
	for (i = m - 2; i >= 0; --i) {
		if (i > g && suff[i + m - 1 - f] < i - g)
			suff[i] = suff[i + m - 1 - f];
		else { 
			if (i < g)
				g = i;
			f = i;
			while (g >= 0 && x[g] == x[g + m - 1 - f])
				--g; 
			suff[i] = f - g;

		}
	}
}

void preBmGs(unsigned char *x, int m, int bmGs[]) 
{
	int i, j, suff[XSIZE];

	suffixes(x, m, suff);
	for (i = 0; i < m; ++i)
		bmGs[i] = m;
	j = 0;
	for (i = m - 1; i >= 0; --i)
		if (suff[i] == i + 1)
				for (; j < m - 1 - i; ++j) 
					if (bmGs[j] == m)
						bmGs[j] = m - 1 - i;

	for (i = 0; i <= m - 2; ++i)
		bmGs[m - 1 - suff[i]] = m - 1 - i;
}

void BM(unsigned char *x, int m,unsigned char *y, int n) {
	int i, j, bmGs[XSIZE], bmBc[ASIZE];

	/* Preprocessing */
	preBmGs(x, m, bmGs);
	preBmBc(x, m, bmBc);

	/* Searching */
	j = 0;
	while (j <= n - m) {
		for (i = m - 1; i >= 0 && x[i] == y[i + j]; --i);
		if (i < 0) {
			offset = j;
			j += bmGs[0];
		}
		else
			j += MAX(bmGs[i], bmBc[y[i + j]] - m + 1 + i);
	}
}
