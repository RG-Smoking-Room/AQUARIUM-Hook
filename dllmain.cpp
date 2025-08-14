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
    auto fix1ptr = ((UINT_PTR)hmoduleOfProcess) + 0x2798C1; // 0x295B51; // Okayu Nyumu!
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

    auto fix2ptr = ((UINT_PTR)hmoduleOfProcess) + 0x1E094E; // 0x1E769E; // Okayu Nyumu!
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

    auto fix3ptr = ((UINT_PTR)hmoduleOfProcess) + 0x1A3BDD; // 0x1B67FD; // Okayu Nyumu!
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

