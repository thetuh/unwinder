#pragma once

namespace util
{
    std::uintptr_t sig_scan( const char* signature, const uintptr_t module_base ) noexcept;
}