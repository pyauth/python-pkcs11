"""
Definitions to support compilation on Windows platform
"""

cdef extern from "Windows.h":
    ctypedef unsigned long DWORD
    ctypedef Py_UNICODE WCHAR
    ctypedef const WCHAR *LPCWSTR
    ctypedef const char *LPCSTR
    ctypedef void *PVOID
    ctypedef PVOID HANDLE
    ctypedef HANDLE HINSTANCE
    ctypedef HINSTANCE HMODULE
    ctypedef bint BOOL

    HMODULE LoadLibraryW(LPCWSTR lpLibFileName)
    BOOL FreeLibrary(HMODULE hLinModule)
    PVOID GetProcAddress(HMODULE hModule, LPCSTR lpProcName)
    DWORD GetLastError()
