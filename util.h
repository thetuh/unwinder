#pragma once

namespace util
{
    bool set_privilege( LPCWSTR privilege, BOOL enable_privilege = TRUE );
    bool pattern_to_bytes( const char* pattern, std::vector<int>& bytes ) noexcept;
    std::uintptr_t sig_scan( const char* signature, const uintptr_t start, const uintptr_t end = 0 ) noexcept;
}