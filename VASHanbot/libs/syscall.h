#pragma once
#include <type_traits>
#pragma comment(lib,"syscall.lib")

namespace syscall
{
    extern"C" void* syscall_stub();

    template<typename T>
    using to_size_t = typename std::conditional<sizeof(T) < sizeof(size_t), size_t, T>::type;

    template<typename... _args>
    long __stdcall call(size_t _idx, _args ...args)
    {
        if (_idx == size_t(-1))
        {
            return 0xC0000225; /*STATUS_NOT_FOUND*/
        }

        auto stub = reinterpret_cast<long(__cdecl *)(size_t, size_t, to_size_t<_args>...)>(syscall_stub);
        return stub(_idx, sizeof...(_args), to_size_t<_args>(args)...);
    }

    size_t index(const char* _fun);
}
