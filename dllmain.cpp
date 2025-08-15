#include "pch.h"

HMODULE hmoduleOfProcess;
bool existLangRu;

using namespace std;

static wstring to_widechar(const string& text, int codepage) {
    const int numBytes = static_cast<int>(text.length());
    const int numChars = MultiByteToWideChar(codepage, 0, text.c_str(), numBytes, nullptr, 0);

    wstring result;
    result.resize(numChars);
    LPWSTR LResult = const_cast<wchar_t*>(result.c_str());
    MultiByteToWideChar(codepage, 0, text.c_str(), numBytes, LResult, numChars);

    return result;
}

static string to_multibyte(const wstring& text, int codepage) {
    const int numChars = text.length();
    const int numBytes = WideCharToMultiByte(codepage, 0, text.c_str(), numChars, nullptr, 0, nullptr, nullptr);

    string result;
    result.resize(numBytes);

    LPSTR LResult = const_cast<char*>(result.c_str());
    WideCharToMultiByte(codepage, 0, text.c_str(), numChars, LResult, numBytes, nullptr, nullptr);

    return result;
}

wstring utf8_to_utf16(const string& utf8)
{
    return to_widechar(utf8, CP_UTF8);
}

string utf16_to_utf8(const wstring& utf16)
{
    return to_multibyte(utf16, CP_UTF8);
}

std::string base_name(std::string const& path)
{
    return path.substr(path.find_last_of("/\\") + 1);
}

bool MemoryCompare(const BYTE* data, const BYTE* datamask, const char* mask)
{
    for (; *mask; ++data, ++datamask, ++mask)
    {
        if (!strcmp(mask, "xxxx"))
        {
            if (*(UINT32*)data != *(UINT32*)datamask)
            {
                return FALSE;
            }

            data += 3, datamask += 3, mask += 3;
            continue;
        }

        if (!strcmp(mask, "xx"))
        {
            if (*(UINT16*)data != *(UINT16*)datamask)
            {
                return FALSE;
            }

            data++, datamask++, mask++;
            continue;
        }

        if (*mask == 'x' && *data != *datamask)
        {
            return false;
        }
    }

    return (*mask) == 0;
}

UINT_PTR FindMemoryPattern(const char* mask, BYTE* datamask, UINT_PTR start, UINT_PTR length)
{
    UINT_PTR end = start + length;

    for (UINT_PTR i = start; i < end; i++)
    {
        if (MemoryCompare((BYTE*)i, datamask, mask))
        {
            return i;
        }
    }

    return 0;
}

PVOID g_pOldCreateFileW = CreateFileW;
typedef int (WINAPI* PfuncCreateFileW)(
    LPCWSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile);

int WINAPI NewCreateFileW(
    LPCWSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile)
{
    if (!existLangRu)
    {
        return ((PfuncCreateFileW)g_pOldCreateFileW)(
            lpFileName,
            dwDesiredAccess,
            dwShareMode,
            lpSecurityAttributes,
            dwCreationDisposition,
            dwFlagsAndAttributes,
            hTemplateFile);
    }
    std::string fName = utf16_to_utf8(lpFileName);
    std::string baseName = base_name(fName);
    if (strcmp(baseName.c_str(), "language.pac") == 0 || strcmp(baseName.c_str(), "Language.pac") == 0 || strcmp(baseName.c_str(), "update-en.pac") == 0 || strcmp(baseName.c_str(), "Update-en.pac") == 0)
    {
        lpFileName = L"Russian.pac";
    }
    return ((PfuncCreateFileW)g_pOldCreateFileW)(
        lpFileName,
        dwDesiredAccess,
        dwShareMode,
        lpSecurityAttributes,
        dwCreationDisposition,
        dwFlagsAndAttributes,
        hTemplateFile);
}

PVOID g_pOldCreateFontW = CreateFontW;
typedef int (WINAPI* PfuncCreateFontW)(int nHeight,
    int nWidth,
    int nEscapement,
    int nOrientation,
    int fnWeight,
    DWORD fdwltalic,
    DWORD fdwUnderline,
    DWORD fdwStrikeOut,
    DWORD fdwCharSet,
    DWORD fdwOutputPrecision,
    DWORD fdwClipPrecision,
    DWORD fdwQuality,
    DWORD fdwPitchAndFamily,
    LPCTSTR lpszFace);
int WINAPI NewCreateFontW(int nHeight,
    int nWidth,
    int nEscapement,
    int nOrientation,
    int fnWeight,
    DWORD fdwltalic,
    DWORD fdwUnderline,
    DWORD fdwStrikeOut,
    DWORD fdwCharSet,
    DWORD fdwOutputPrecision,
    DWORD fdwClipPrecision,
    DWORD fdwQuality,
    DWORD fdwPitchAndFamily,
    LPCTSTR lpszFace)
{
    if (nHeight == -40) { nHeight = 42; }
    fdwCharSet = ANSI_CHARSET;
    return ((PfuncCreateFontW)g_pOldCreateFontW)(nHeight,
        nWidth,
        nEscapement,
        nOrientation,
        fnWeight,
        fdwltalic,
        fdwUnderline,
        fdwStrikeOut,
        fdwCharSet,
        fdwOutputPrecision,
        fdwClipPrecision,
        fdwQuality,
        fdwPitchAndFamily,
        lpszFace);
}

void Hook()
{
    DWORD dwProtect;

    BYTE patternfix1[] = { 0x7F, 0x76, 0x54, 0x3C, 0xEF, 0x0F, 0x85, 0x0F, 0x01, 0x00, 0x00, 0x83, 0xFF, 0x02, 0x7E, 0x47, 0x8A, 0x51, 0x01, 0x8A, 0xC2, 0x04, 0x5C, 0x3C, 0x1A };
    UINT_PTR ptrfix1 = FindMemoryPattern("xxxxxxxxxxxxxxxxxxxxxxxxx", patternfix1, ((UINT_PTR)hmoduleOfProcess), 0x300000);
    if (ptrfix1 != 0)
    {
        //auto fix1ptr = ((UINT_PTR)hmoduleOfProcess) + 0x295B51;
        auto fix1ptr = ptrfix1;
        if (VirtualProtect((PVOID&)fix1ptr, 1, PAGE_EXECUTE_READWRITE, &dwProtect))
        {
            memset((PVOID&)fix1ptr, 0xD1, 1);
            VirtualProtect((PVOID&)fix1ptr, 1, dwProtect, &dwProtect);
            std::cout << "Cyrillic Fix1 Done" << std::endl;
        }
        else
        {
            std::cout << "Cyrillic Fix1 Failed" << std::endl;
        }
    }
    else
    {
        std::cout << "Cyrillic Fix1 Search Failed" << std::endl;
    }

    BYTE patternfix2[] = { 0x02, 0x80, 0xF9, 0xC1, 0x0F, 0x86, 0xD3, 0x00, 0x00, 0x00, 0x80, 0xF9, 0xDF, 0x0F, 0x87, 0xB0, 0x00, 0x00, 0x00, 0xB9, 0x02, 0x00, 0x00, 0x00, 0xE9 };
    UINT_PTR ptrfix2 = FindMemoryPattern("xxxxxxxxxxxxxxxxxxxxxxxxx", patternfix2, ((UINT_PTR)hmoduleOfProcess), 0x300000);
    if (ptrfix2 != 0)
    {
        //auto fix2ptr = ((UINT_PTR)hmoduleOfProcess) + 0x1E769E;
        auto fix2ptr = ptrfix2;
        if (VirtualProtect((PVOID&)fix2ptr, 1, PAGE_EXECUTE_READWRITE, &dwProtect))
        {
            memset((PVOID&)fix2ptr, 0x01, 1);
            VirtualProtect((PVOID&)fix2ptr, 1, dwProtect, &dwProtect);
            std::cout << "Cyrillic Fix2 Done" << std::endl;
        }
        else
        {
            std::cout << "Cyrillic Fix2 Failed" << std::endl;
        }
    }
    else
    {
        std::cout << "Cyrillic Fix2 Search Failed" << std::endl;
    }

    BYTE patternfix3[] = { 0x0F, 0x85, 0xCA, 0x00, 0x00, 0x00, 0xF6, 0x45, 0x10, 0x04, 0x0F, 0x84, 0xC0, 0x00, 0x00, 0x00, 0x83, 0xC1, 0x1C, 0x8B, 0xD1, 0x8D, 0x72, 0x02, 0x66 };
    UINT_PTR ptrfix3 = FindMemoryPattern("xxxxxxxxxxxxxxxxxxxxxxxxx", patternfix3, ((UINT_PTR)hmoduleOfProcess), 0x300000);
    if (ptrfix3 != 0)
    {
        //auto fix3ptr = ((UINT_PTR)hmoduleOfProcess) + 0x1B67FD;
        auto fix3ptr = ptrfix3;
        if (VirtualProtect((PVOID&)fix3ptr, 6, PAGE_EXECUTE_READWRITE, &dwProtect))
        {
            memset((PVOID&)fix3ptr, 0x90, 6);
            VirtualProtect((PVOID&)fix3ptr, 1, dwProtect, &dwProtect);
            std::cout << "Font Fix Done" << std::endl;
        }
        else
        {
            std::cout << "Font Fix Failed" << std::endl;
        }
    }
    else
    {
        std::cout << "Font Fix Search Failed" << std::endl;
    }

    BYTE patternfix4[] = { 0x02, 0x00, 0x00, 0x00, 0xEB, 0x5C, 0x8D, 0x41, 0x02, 0x3B, 0xC6, 0x7C, 0x05, 0x83, 0xC8, 0xFF, 0xEB, 0x50, 0x8A, 0x62, 0x01, 0x8A, 0xC4, 0x04, 0x5C };
    UINT_PTR ptrfix4 = FindMemoryPattern("xxxxxxxxxxxxxxxxxxxxxxxxx", patternfix4, ((UINT_PTR)hmoduleOfProcess), 0x300000);
    if (ptrfix4 != 0)
    {
        auto fix4ptr = ptrfix4;
        if (VirtualProtect((PVOID&)fix4ptr, 1, PAGE_EXECUTE_READWRITE, &dwProtect))
        {
            memset((PVOID&)fix4ptr, 0x01, 1);
            VirtualProtect((PVOID&)fix4ptr, 1, dwProtect, &dwProtect);
            std::cout << "Cyrillic Fix4 Done" << std::endl;
        }
        else
        {
            std::cout << "Cyrillic Fix4 Failed" << std::endl;
        }
    }
    else
    {
        std::cout << "Cyrillic Fix4 Search Failed" << std::endl;
    }

    DetourTransactionBegin();
    DetourAttach(&g_pOldCreateFontW, NewCreateFontW);
    DetourAttach(&g_pOldCreateFileW, NewCreateFileW);
    DetourTransactionCommit();

}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:

        //AllocConsole();
        //freopen("conin$", "r", stdin);
        //freopen("conout$", "w", stdout);
        //freopen("conout$", "w", stderr);

        Proxy::Init(hModule);

        existLangRu = std::filesystem::exists("Russian.pac");
        hmoduleOfProcess = GetModuleHandle(0);

        Hook();



    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

