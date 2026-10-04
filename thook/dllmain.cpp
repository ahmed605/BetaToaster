// dllmain.cpp : Defines the entry point for the DLL application.
#include "framework.h"
#include <Objbase.h>
#include <format>

#include <KNSoft/SlimDetours/detours.h>
#pragma comment(lib, "Microsoft.Detours.lib")

// 60014524-3f6b-4be2-b831-20017df88bae
static const constexpr GUID IID_ITileRenderingData =
{ 0x60014524, 0x3f6b, 0x4be2, { 0xb8, 0x31, 0x20, 0x01, 0x7d, 0xf8, 0x8b, 0xae } };

__declspec(dllexport) void __stdcall Install();

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
        CreateThread(nullptr, 0, [](LPVOID) -> DWORD
            {
                Install();
                return 0;
            }, nullptr, 0, nullptr);
        break;
    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

struct Struct_1
{
    BSTR AppMoniker;
    int64_t NotificationId;
    unsigned __int8* Payload;
    int64_t PayloadLength;
};

struct __declspec(uuid("26f7a762-37d0-45bc-ad6e-a14f5d147c59")) IWpnPresentationToastSink : public IUnknown
{
    virtual HRESULT WINAPI ToastSessionUpdated(Struct_1* p0) PURE;
};

decltype(&::CoMarshalInterThreadInterfaceInStream) ogCoMarshalInterThreadInterfaceInStream = nullptr;
decltype(&::CoGetInterfaceAndReleaseStream) ogCoGetInterfaceAndReleaseStream = nullptr;

HRESULT WINAPI CoMarshalInterThreadInterfaceInStreamHook(REFIID riid, IUnknown* pUnk, IStream** ppStm)
{
    if (riid == IID_ITileRenderingData)
    {
        return pUnk->QueryInterface(riid, (void**)ppStm);
    }

    return ogCoMarshalInterThreadInterfaceInStream(riid, pUnk, ppStm);
}

HRESULT WINAPI CoGetInterfaceAndReleaseStreamHook(IStream* pStm, REFIID riid, void** ppv)
{
    if (ppv && riid == IID_ITileRenderingData)
    {
        *ppv = pStm;
        return S_OK;
    }

    return ogCoGetInterfaceAndReleaseStream(pStm, riid, ppv);
}

static char* PatternScan(_In_reads_(size) char* start,
                         size_t size,
                         _In_reads_(patternSize) uint16_t* patternBytes,
                         size_t patternSize)
{
    if (patternSize > size) [[unlikely]]
        return nullptr;

    for (size_t i = 0; i <= size - patternSize; ++i)
    {
        bool found = true;
        for (size_t j = 0; j < patternSize; ++j)
        {
            if (patternBytes[j] != UINT16_MAX && start[i + j] != static_cast<char>(patternBytes[j]))
            {
                found = false;
                break;
            }
        }

        if (found) return &start[i];
    }

    return nullptr;
}

static char* PatternScan(HMODULE mod, _In_reads_(patternSize) uint16_t* patternBytes, size_t patternSize)
{
    auto modBase   = (uintptr_t)((uintptr_t)mod &~ uintptr_t(0x3));
    auto dosHeader = (PIMAGE_DOS_HEADER)modBase;
    auto ntHeaders = (PIMAGE_NT_HEADERS)(modBase + dosHeader->e_lfanew);
    auto codeSize  = ntHeaders->OptionalHeader.SizeOfCode;
    auto codeBase  = (char*)(modBase + ntHeaders->OptionalHeader.BaseOfCode);
    return PatternScan(codeBase, codeSize, patternBytes, patternSize);
}

#pragma warning(disable : 4996)
__declspec(dllexport) void __stdcall Install()
{
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);

    auto mod = GetModuleHandleW(L"twinui.dll");
    auto DllGetClassObject = (decltype(&::DllGetClassObject))GetProcAddress(mod, "DllGetClassObject");

    if (!DllGetClassObject)
    {
        MessageBoxW(nullptr, L"Failed to get DllGetClassObject from twinui.dll", L"thook", MB_OK);
        return;
    }

    auto ole32 = GetModuleHandleW(L"ole32.dll");
    ogCoMarshalInterThreadInterfaceInStream = (decltype(&::CoMarshalInterThreadInterfaceInStream))GetProcAddress(ole32, "CoMarshalInterThreadInterfaceInStream");
    ogCoGetInterfaceAndReleaseStream = (decltype(&::CoGetInterfaceAndReleaseStream))GetProcAddress(ole32, "CoGetInterfaceAndReleaseStream");

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach((void**)&ogCoMarshalInterThreadInterfaceInStream, CoMarshalInterThreadInterfaceInStreamHook);
    DetourAttach((void**)&ogCoGetInterfaceAndReleaseStream, CoGetInterfaceAndReleaseStreamHook);
    auto commit = DetourTransactionCommit();

    auto fmt = std::format(L"DetourTransactionCommit: 0x{:X}", (DWORD)commit);
    MessageBoxW(nullptr, fmt.c_str(), L"thook", MB_OK);

    // 48 8D 0D ?? ?? ?? ?? 45 33 C9 45 33 C0 33 D2
    static uint16_t pattern[] = { 0x48, 0x8D, 0x0D, UINT16_MAX, UINT16_MAX, UINT16_MAX, UINT16_MAX, 0x45, 0x33, 0xC9, 0x45, 0x33, 0xC0, 0x33, 0xD2 };
    
    if (auto patternResult = PatternScan(mod, pattern, _countof(pattern)))
    {
        // lea rcx, CToastManager::s_ToastHostWndProc (7 bytes)
        auto rel = *(int32_t*)((uintptr_t)patternResult + 3);
        auto wndProc = (void*)((uintptr_t)patternResult + 7 + rel);
        fmt = std::format(L"Found s_ToastHostWndProc: 0x{:X}", (uintptr_t)wndProc);
        MessageBoxW(nullptr, fmt.c_str(), L"thook", MB_OK);

        bool foundHwnd = false;
        auto currentPid = GetCurrentProcessId();
        HWND hWnd = FindWindowExW(NULL, NULL, L"WorkerW", NULL);
        while (hWnd)
        {
            DWORD pid = 0;
            GetWindowThreadProcessId(hWnd, &pid);

            if (pid == currentPid &&
                GetWindowLongPtrW(hWnd, GWLP_WNDPROC) == (LONG_PTR)wndProc)
            {
                foundHwnd = true;
                break;
            }

            hWnd = FindWindowExW(NULL, hWnd, L"WorkerW", NULL);
        }

        if (foundHwnd && hWnd)
        {
            fmt = std::format(L"Found WorkerW window: 0x{:X}", (uintptr_t)hWnd);
            MessageBoxW(nullptr, fmt.c_str(), L"thook", MB_OK);

            if (auto manager = GetWindowLongPtrW(hWnd, -21))
            {
                fmt = std::format(L"Found CToastManager: 0x{:X}", (uintptr_t)manager);
                MessageBoxW(nullptr, fmt.c_str(), L"thook", MB_OK);

                if (auto notificationManager = *(void**)(((uintptr_t)manager) + 0x38))
                {
                    fmt = std::format(L"Found CToastNotificationManager: 0x{:X}", (uintptr_t)notificationManager);
                    MessageBoxW(nullptr, fmt.c_str(), L"thook", MB_OK);

                    if (auto session = *(IWpnPresentationToastSink**)(((uintptr_t)notificationManager) + 0x10))
                    {
                        fmt = std::format(L"Found CToastSession: 0x{:X}", (uintptr_t)session);
                        MessageBoxW(nullptr, fmt.c_str(), L"thook", MB_OK);

                        OSVERSIONINFOEXW info { sizeof(OSVERSIONINFOEXW) };
                        GetVersionExW((LPOSVERSIONINFOW)&info);

                        auto moniker = SysAllocString(L"Microsoft.InternetExplorer.Default");

                        Struct_1 toastSession = { NULL };
                        toastSession.NotificationId = 321;
                        toastSession.AppMoniker = moniker;
                        auto payload = std::format(
                            R"(<?xml version="1.0"?>
                            <Toast>
                              <audio></audio>
                              <appspace version="1" color="white" background-color="black">

                                <text
                                    left="0"
                                    top="20"
                                    width="300"
                                    height="70"
                                    color="white"
                                    font-size="24.0pt"
                                    font-weight="bold"
                                    font-family="Segoe UI">Hello from {}!</text>

                                <text
                                    left="0"
                                    top="60"
                                    width="300"
                                    height="100"
                                    color="silver"
                                    font-size="14.0pt"
                                    font-family="Segoe UI">We can <format text-decoration="line-through">also</format> do a <format font-style="italic">little</format> <format color="lime">bit</format> of <format font-family="Comic Sans MS">styling</format>.</text>

                                <launch action="https://google.com" />

                              </appspace>
                            </Toast>)", info.dwBuildNumber);

                        toastSession.Payload = (unsigned __int8*)payload.c_str();
                        toastSession.PayloadLength = payload.length();

                        auto result = session->ToastSessionUpdated(&toastSession);
                        fmt = std::format(L"ToastSessionUpdated result: 0x{:X}", (DWORD)result);
                        MessageBoxW(nullptr, fmt.c_str(), L"thook", MB_OK);
                        SysFreeString(moniker);
                    }
                }
            }
        }
    }
}

