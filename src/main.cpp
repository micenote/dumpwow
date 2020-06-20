/*
    MIT License

    Copyright (c) 2020 namreeb (legal@namreeb.org) http://github.com/namreeb/dumpwow

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
*/
#define _SILENCE_EXPERIMENTAL_FILESYSTEM_DEPRECATION_WARNING

#include "raii_proc.hpp"

#include <BlackBone/Process/Process.h>
#include <BlackBone/Patterns/PatternSearch.h>

#include <Windows.h>
#include <intrin.h>

#include <iostream>
#include <vector>
#include <string>
#include <experimental/filesystem>
#include <thread>
#include <chrono>
#include <fstream>
#include <cstdio>
#include <atomic>
#include <cstdint>

#pragma intrinsic(_ReturnAddress)

#define CALL_FIRST  1

namespace fs = std::experimental::filesystem;

std::vector<std::uint8_t> find_wow_pe(blackbone::Process &process);
BOOL ControlHandler(DWORD ctrl_type);
bool FindVEHCallerRVA();
size_t find_call_tls_initializers_rva();
void process_log_file(const fs::path &exe_path);

size_t g_veh_caller_rva;
std::atomic_bool g_exit_wow;

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        std::cerr << "Usage: " << argv[0] << " <wow.exe>" << std::endl;
        return EXIT_FAILURE;
    }

    auto const call_tls_initializers_rva = find_call_tls_initializers_rva();

    if (!call_tls_initializers_rva)
    {
        std::cerr << "Failed to find LdrpCallTlsInitializers" << std::endl;
        return EXIT_FAILURE;
    }

    const fs::path path(argv[1]);

    try
    {
        blackbone::Process wow;
        wow.CreateAndAttach(path, true);

        // ensure process is killed upon exit
        const RaiiProc proc_killer(wow.pid());

        auto pe_file_buff = find_wow_pe(wow);

        blackbone::pe::PEImage pe;
        pe.Load(&pe_file_buff[0], pe_file_buff.size(), false);

        // temporarily disable TLS callbacks to prevent them from executing
        // when we inject
/*        auto const tls_callback_directory =
            find_tls_callback_directory(process, pe_file);


        if (!tls_callback_directory)
        {
            std::cerr << "Unable to find TLS callback directory" << std::endl;
            return EXIT_FAILURE;
        }

        std::cout << "TLS callback directory: 0x" << std::hex
            << reinterpret_cast<std::uintptr_t>(tls_callback_directory)
            << std::endl;

        auto const first_callback = hadesmem::Read<void *>(process,
            tls_callback_directory);

        std::cout << "First TLS callback:     0x" << std::hex
            << reinterpret_cast<std::uintptr_t>(first_callback)
            << std::endl;

        hadesmem::Write<void *>(process, tls_callback_directory, nullptr);

        auto const verify = hadesmem::Read<void *>(process,
            tls_callback_directory);

        if (verify)
        {
            std::cerr << "Failed to zero first TLS callback" << std::endl;
            return EXIT_FAILURE;
        }

        // with the TLS callbacks disabled, our DLL may be safely injected
        const hadesmem::Module unpacker(process, hadesmem::InjectDll(process,
            L"unpacker.dll", hadesmem::InjectFlags::kPathResolution));

        // call init function in DLL
        auto const func = reinterpret_cast<
            void(*)(size_t, DWORD, PVOID, DWORD)>(
            hadesmem::FindProcedure(process, unpacker, "Initialize"));

        hadesmem::Call(process, func, hadesmem::CallConv::kDefault,
            call_tls_initializers_rva, proc_info.dwThreadId,
            pe_file.GetBase(), pe_file.GetSize());

        // restore first TLS callback
        hadesmem::Write<void *>(process, tls_callback_directory,
            first_callback);
            */
        if (!::SetConsoleCtrlHandler(ControlHandler, TRUE))
        {
            std::cerr << "SetConsoleCtrlHandler failed" << std::endl;
            return EXIT_FAILURE;
        }

        if (wow.Resume() != STATUS_SUCCESS)
        {
            std::cerr << "Failed to resume main thread" << std::endl;
            return EXIT_FAILURE;
        }

        DWORD exit_code = 0;

        do
        {
            if (g_exit_wow)
            {
                g_exit_wow = false;
                std::cout << "Received CTRL-C.  Terminating wow..."
                    << std::endl;
                if (wow.Terminate(0) != STATUS_SUCCESS)
                {
                    std::cerr << "TerminateProcess failed" << std::endl;
                    return EXIT_FAILURE;
                }
            }

            if (!::GetExitCodeProcess(wow.core().handle(), &exit_code))
            {
                std::cerr << "GetExitCodeProcess failed" << std::endl;
                return EXIT_FAILURE;
            }

            // if there is a different exit code, the process has exited
            if (exit_code != STILL_ACTIVE)
                break;

            // if STILL_ACTIVE is the exit code, the process may have chosen to
            // exit using that error code, so try one more check
            if (::WaitForSingleObject(wow.core().handle(), 0) != WAIT_TIMEOUT)
                break;

            // if the waiting timed out, it means the process is still running.
            // so let us sleep for a little while and then check again
            std::this_thread::sleep_for(std::chrono::milliseconds(300));
        } while (true);

        if (!::SetConsoleCtrlHandler(ControlHandler, FALSE))
        {
            std::cerr << "SetConsoleCtrlHandler failed" << std::endl;
            return EXIT_FAILURE;
        }

        std::cout << "Wow exited with code:   0x" << std::hex << exit_code
            << std::endl;

        process_log_file(path);
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error: " << e.what() << std::endl;
        process_log_file(path);
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

LONG NTAPI VectoredExceptionHandler(struct _EXCEPTION_POINTERS *exceptionInfo)
{
    auto const return_address = reinterpret_cast<const std::uint8_t *>(
        ::_ReturnAddress());
    auto const base = reinterpret_cast<const std::uint8_t *>(
        ::GetModuleHandle(L"ntdll"));

    g_veh_caller_rva = return_address - base - 6;

    return EXCEPTION_CONTINUE_EXECUTION;
}

// find the RVA of RtlpCallVectoredHandlers within NTDLL so we know where to
// find it once we launch wow
bool FindVEHCallerRVA()
{
    // first, add our own VEH
    auto const veh_handle = ::AddVectoredExceptionHandler(CALL_FIRST,
        &VectoredExceptionHandler);

    // second, raise an exception
    ::RaiseException(1, 0, 0, nullptr);

    // third, remove the VEH
    if (!::RemoveVectoredExceptionHandler(veh_handle))
        return false;

    // at this point, g_veh_caller_rva will have a value.  now check if it is
    // valid
    auto const call_site = reinterpret_cast<std::uint8_t *>(
        GetModuleHandle(L"ntdll")) + g_veh_caller_rva;

    // first byte of indirect call instruction is right?
    return *call_site == 0xFF && *(call_site + 5) == 0;
}

std::vector<std::uint8_t> find_wow_pe(blackbone::Process &process)
{
    auto &wow_memory = process.memory();
    auto const regions = wow_memory.EnumRegions();

    // find the PE header for wow
    for (auto const &region : regions)
    {
        if (region.Type != MEM_IMAGE)
            continue;

        if (region.Protect != PAGE_READONLY)
            continue;

        if (region.AllocationBase != region.BaseAddress)
            continue;

        std::vector<std::uint8_t> pe_data(region.RegionSize);
        if (wow_memory.Read(region.BaseAddress, pe_data.size(), &pe_data[0]) !=
            STATUS_SUCCESS)
            continue;

        blackbone::pe::PEImage pe;
        pe.Load(&pe_data[0], pe_data.size(), false);

        auto const tls_dir = pe.DirectoryAddress(IMAGE_DIRECTORY_ENTRY_TLS);

        if (!tls_dir)
            continue;

        std::cout << "Wow base address:       0x" << std::hex
            << region.BaseAddress << std::endl;

        return std::move(pe_data);
    }

    throw std::runtime_error("Could not find wow PE");
}

size_t find_call_tls_initializers_rva()
{
    auto const ntdll = ::GetModuleHandle(L"ntdll");

    if (!ntdll)
        return 0;

    blackbone::Process process;
    process.Attach(::GetCurrentProcess());

    // find "LdrpCallTlsInitializers"
    blackbone::PatternSearch first_pattern(
        "\x4C\x64\x72\x70\x43\x61\x6C\x6C\x54\x6C\x73\x49"
        "\x6E\x69\x74\x69\x61\x6C\x69\x7A\x65\x72\x73\x00");

    std::vector<blackbone::ptr_t> out;
    first_pattern.Search(ntdll, 0xFFFFFF, out);

    if (out.empty())
        return 0;

    auto p_LdrpCallTlsInitializers = reinterpret_cast<void*>(out[0]);

    const std::uint8_t *magic_value_ref = nullptr;

    blackbone::PatternSearch deref_pattern("\x4C\x8D\x05???\x00");

    // find recurrences of the byte pattern which dereferences the magic value
    // and check for one that actually is dereferencing it
    deref_pattern.Search(p_LdrpCallTlsInitializers, 0xFFFF, out);

    for (auto const &p : out)
    {
        auto const p_offset = reinterpret_cast<std::uintptr_t *>(p) -
            reinterpret_cast<std::uintptr_t *>(ntdll);

        auto const expected_offset = static_cast<std::uint32_t>(
            reinterpret_cast<std::uintptr_t>(p_LdrpCallTlsInitializers) - p)
            - 7;

        auto const offset = *reinterpret_cast<std::uint32_t*>(p + 3);

        if (offset == expected_offset)
        {
            magic_value_ref = reinterpret_cast<const std::uint8_t *>(p);
            break;
        }
    }

    // not found?  give up
    if (!magic_value_ref)
        return 0;

    const std::uint8_t *func = nullptr;

    // begin searching backwards for a few INT3 (0xCC) instructions to guess at
    // the start of the function
    for (int offset = 0; offset < 0x200; ++offset)
    {
        auto const p = reinterpret_cast<const std::uint8_t *>(magic_value_ref)
            - offset;

        if (*(p - 0) != 0xCC &&
            *(p - 1) == 0xCC &&
            *(p - 2) == 0xCC &&
            *(p - 3) == 0xCC &&
            *(p - 4) == 0xCC)
        {
            func = p;
            break;
        }
    }

    // function start not found?  give up
    if (!func)
        return 0;

    return static_cast<std::uint64_t>(func -
        reinterpret_cast<const std::uint8_t *>(ntdll));
}

void process_log_file(const fs::path &exe_path)
{
    auto const parent = exe_path.parent_path();
    auto const log_path = parent / "log.txt";

    std::ifstream in(log_path, std::ios::ate);

    if (!in)
    {
        std::cerr << "Failed to read " << log_path << std::endl;
        return;
    }

    auto const file_size = static_cast<size_t>(in.tellg());
    in.seekg(std::ios::beg);

    std::vector<char> file_data(file_size + 1);
    in.read(&file_data[0], file_data.size());
    file_data[file_data.size() - 1] = '\0';
    in.close();


    std::cout << "\nLog:\n\n" << &file_data[0];

    std::remove(log_path.string().c_str());
}

BOOL ControlHandler(DWORD ctrl_type)
{
    if (ctrl_type == CTRL_C_EVENT)
    {
        g_exit_wow = true;
        return TRUE;
    }

    std::cout << "Received unrecognized event: " << std::dec << ctrl_type
        << std::endl;

    return FALSE;
}
