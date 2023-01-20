// MomiCrack.cpp : 이 파일에는 'main' 함수가 포함됩니다. 거기서 프로그램 실행이 시작되고 종료됩니다.
//

#include <iostream>
#include <windows.h>
#include <TlHelp32.h>
#include <conio.h>

#define SAVE_WND_SIZE 900

DWORD FindProcessID(LPCTSTR szProcessName);
BOOL EnablePriv(LPCWSTR lpszPriv);
void gotoxy(int x, int y);
void printMenu(const char* log);

using namespace std;

char asm_code[] = 
"\x50\x8b\x00\x50\x68"
"\x00\x00\x00\x00" // 비밀번호는 %s 입니다 문자열 주소(LE), asm_code + 5
"\x68"
"\x00\x00\x00\x00" // 비밀번호는 asdf 입니다 메모리 공간 주소(LE), asm_code + 10
"\xe8"
"\x00\x00\x00\x00" // swprintf 상대주소, asm_code + 15
"\x83\xc4\x0c\x58\xe9"
"\x00\x00\x00\x00";// 0x4297a1 상대주소, asm_code + 24
int len_asm_code = 29;

int main()
{
	system("mode con cols=40 lines=20");

	if (!EnablePriv(SE_DEBUG_NAME))
	{
		cout << "디버그 권한 획득 실패" << endl;
		_getch();
		return 0;
	}

	cout << endl;
	cout << " 맘아이 그린 5.0 크랙 by 플래그모" << endl;
	cout << endl;
	cout << " 맘아이를 식별하기 위해" << endl;
	cout << " 부모모드 로그인 창을 선택해주세요" << endl;

	HWND saveWnd[SAVE_WND_SIZE];
	UINT SAVE_WND_LEN = 0;
	HANDLE hOsp;

	char str[100] = "";

	/* 윈도우 선택을 감시하며 맘아이 프로세스인지 여부 검사 */
	while (1)
	{
		UINT i;
		HWND hWnd = GetForegroundWindow();	Sleep(150);

		for (i = 0; i < SAVE_WND_LEN; i++) // HWND 리스트를 돌며 비교
		{
			if (saveWnd[i] == hWnd)
				break;
		}
		if (i >= SAVE_WND_LEN) // HWND 리스트에서 발견되지 않았으면
		{
			DWORD pid;
			GetWindowThreadProcessId(hWnd, &pid);
			if (SAVE_WND_LEN < SAVE_WND_SIZE)
				saveWnd[SAVE_WND_LEN++] = hWnd; // HWND 리스트에 추가

			hOsp = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
			if (!hOsp)
			{
				cout << "프로세스를 여는데 실패했습니다. 코드 : " << GetLastError() << endl;
				_getch();
				return 0;
			}
			ReadProcessMemory(hOsp, (LPVOID)0x429597, str, 11, NULL);
			if (!memcmp(str, "\x8b\x85\x2c\xff\xff\xff\x05\x9c\x03\x00\x00", 11)) // 시그니처 기반 검사, 맘아이인지 확인
				break; // 창 감시 종료

			CloseHandle(hOsp);
		}
	}

	cout << " 맘아이 발견됨" << endl;
	Sleep(4000);

	printMenu("");
	while (1)
	{
		char input;
		do input = _getch(); while (input < '1' || '2' < input);
		cout << input << endl;
		Sleep(600);

		LPVOID pwIs, pwIsAsdf, codepage;

		switch (input)
		{
		case '1':
			{
			pwIs = VirtualAllocEx(hOsp, NULL, 100, MEM_COMMIT, PAGE_READWRITE);
			pwIsAsdf = VirtualAllocEx(hOsp, NULL, 100, MEM_COMMIT, PAGE_READWRITE);
			codepage = VirtualAllocEx(hOsp, NULL, len_asm_code, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

			const wchar_t* strPwIs = TEXT("비밀번호는 %s입니다.\n다시 입력해주세요");
			WriteProcessMemory(hOsp, pwIs, strPwIs, wcslen(strPwIs) * 2 + 2, NULL); // 문자열 삽입

			/* 어셈블리 코드 주입 */

			*(DWORD*)(asm_code + 5) = (DWORD)pwIs; // 어셈코드의 "비밀번호는 %s입니다" 문자열 주소값 수정
			*(DWORD*)(asm_code + 10) = (DWORD)pwIsAsdf; // 어셈코드의 "비밀번호는 asdf입니다" 메모리 공간 주소값 수정
			*(DWORD*)(asm_code + 24) = 0x4297a1 - ((DWORD)codepage + 28); // proc 0x4297a1 상대주소 계산

			HMODULE hMod = LoadLibraryA("msvcrt.dll");
			*(DWORD*)(asm_code + 15) = (DWORD)GetProcAddress(hMod, "swprintf")
				- ((DWORD)codepage + 19); // 어셈코드의 call swprintf 상대주소 값 수정

			WriteProcessMemory(hOsp, codepage, asm_code, len_asm_code, NULL);

			/* 로그인 이벤트 코드 변조 */

			DWORD dwOld;
			VirtualProtectEx(hOsp, (LPVOID)0x42943c, 0xb7c, PAGE_EXECUTE_READWRITE, &dwOld);

			// 훅 설치
			str[0] = '\xe9';
			*(DWORD*)(str + 1) = (DWORD)codepage - 0x4297a1;
			WriteProcessMemory(hOsp, (LPVOID)0x42979c, str, 5, NULL);

			// 로그인 실패 메시지 교체
			str[0] = '\x68';
			*(DWORD*)(str + 1) = (DWORD)pwIsAsdf;
			WriteProcessMemory(hOsp, (LPVOID)0x429ce8, str, 5, NULL);

			printMenu("크랙 수행됨,\n 로그인을 시도해주세요");
			break;
			}
		case '2' :
			{
			/* 로그인 이벤트 코드 원상복구 */

			str[0] = '\xe8';
			*(DWORD*)(str + 1) = 0x1eaad3;
			WriteProcessMemory(hOsp, (LPVOID)0x42979c, str, 5, NULL);

			// 로그인 실패 메시지 교체
			str[0] = '\x68';
			*(DWORD*)(str + 1) = 0x67978c;
			WriteProcessMemory(hOsp, (LPVOID)0x429ce8, str, 5, NULL);

			printMenu("크랙 해제됨");
			break;
			}
		default :
			break;
		}
	}
}

DWORD FindProcessID(LPCTSTR szProcessName)
{
	DWORD dwPID = -1;
	HANDLE hSnapShot = INVALID_HANDLE_VALUE;
	PROCESSENTRY32 pe;

	pe.dwSize = sizeof(PROCESSENTRY32);
	hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, NULL);

	Process32First(hSnapShot, &pe); // 전체 프로세스의 정보들을 받아옴
	do
	{
		if (!wcscmp(szProcessName, pe.szExeFile)) // 프로세스 이름 ex) notepad.exe 이 맞는지 비교
		{
			dwPID = pe.th32ProcessID;
			break;
		}
	} while (Process32Next(hSnapShot, &pe)); // 다음 포로세스 정보를 받아옴

	CloseHandle(hSnapShot);

	return dwPID;
}

BOOL EnablePriv(LPCWSTR lpszPriv)
{
	HANDLE hToken;
	LUID luid;
	TOKEN_PRIVILEGES tkprivs;
	ZeroMemory(&tkprivs, sizeof(tkprivs));

	if (!OpenProcessToken(GetCurrentProcess(), (TOKEN_ADJUST_PRIVILEGES
		| TOKEN_QUERY), &hToken))
		return FALSE;

	if (!LookupPrivilegeValue(NULL, lpszPriv, &luid)) {
		CloseHandle(hToken); return FALSE;
	}

	tkprivs.PrivilegeCount = 1;
	tkprivs.Privileges[0].Luid = luid;
	tkprivs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	BOOL bRet = AdjustTokenPrivileges(hToken, FALSE, &tkprivs,
		sizeof(tkprivs), NULL, NULL);
	CloseHandle(hToken);
	return bRet;
}
void gotoxy(int x, int y)
{
	COORD Pos;
	Pos.X = x;
	Pos.Y = y;
	SetConsoleCursorPosition(GetStdHandle(STD_OUTPUT_HANDLE), Pos);
}
void printMenu(const char* log)
{
	system("cls");

	cout << endl;
	cout << " 맘아이 그린 5.0 크랙 by 플래그모" << endl;
	cout << endl;
	cout << " 1. 비밀번호 크랙 시작" << endl;
	cout << " 2. 비밀번호 크랙 해제" << endl;
	cout << endl;
	cout << " >>" << endl;
	cout << endl;
	cout << ' ' << log;

	gotoxy(4, 6);
}
// 프로그램 실행: <Ctrl+F5> 또는 [디버그] > [디버깅하지 않고 시작] 메뉴
// 프로그램 디버그: <F5> 키 또는 [디버그] > [디버깅 시작] 메뉴

// 시작을 위한 팁: 
//   1. [솔루션 탐색기] 창을 사용하여 파일을 추가/관리합니다.
//   2. [팀 탐색기] 창을 사용하여 소스 제어에 연결합니다.
//   3. [출력] 창을 사용하여 빌드 출력 및 기타 메시지를 확인합니다.
//   4. [오류 목록] 창을 사용하여 오류를 봅니다.
//   5. [프로젝트] > [새 항목 추가]로 이동하여 새 코드 파일을 만들거나, [프로젝트] > [기존 항목 추가]로 이동하여 기존 코드 파일을 프로젝트에 추가합니다.
//   6. 나중에 이 프로젝트를 다시 열려면 [파일] > [열기] > [프로젝트]로 이동하고 .sln 파일을 선택합니다.
