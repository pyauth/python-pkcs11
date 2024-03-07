#!python
#cython: language_level=3
#
# MIT License
#
# Copyright 2019 Eric Devolder
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

"""
Definitions to support compilation on Windows platform
"""

from cpython cimport unicode, wchar_t

cdef extern from "Windows.h":
    ctypedef unsigned long DWORD

    ctypedef wchar_t *LPWSTR
    ctypedef const wchar_t *LPCWSTR
    
    ctypedef void* PVOID
    ctypedef const void* LPCVOID

    ctypedef PVOID HANDLE
    ctypedef HANDLE HLOCAL
    ctypedef HANDLE HINSTANCE
    ctypedef HANDLE HMODULE

    ctypedef bint BOOL
    ctypedef short INT16

    ctypedef unsigned long DWORD

    ctypedef enum LANG_ID:
        LANG_NEUTRAL
        LANG_USER_DEFAULT
        SUBLANG_DEFAULT

    ctypedef enum FORMAT_FLAGS:
        FORMAT_MESSAGE_ALLOCATE_BUFFER
        FORMAT_MESSAGE_FROM_SYSTEM
        FORMAT_MESSAGE_IGNORE_INSERTS

    HMODULE LoadLibraryW(LPCWSTR lpLibFileName)
    BOOL FreeLibrary(HMODULE hLinModule)
    PVOID GetProcAddress(HMODULE hModule, const char* lpProcName)
    DWORD GetLastError()

    DWORD MAKELANGID(INT16 p, INT16 s)
    DWORD FormatMessageW(
        DWORD   dwFlags,
        LPCVOID lpSource,
        DWORD   dwMessageId,
        DWORD   dwLanguageId,
        LPWSTR  lpBuffer,
        DWORD   nSize,
        ...
    )

    HLOCAL LocalFree(HLOCAL handle)

cdef inline winerror(so) with gil:
    """
    returns the last error message, as a string.
    If the string has '%1', it is substituted with the content of 'so' arg.
    """
    #
    # inspired from https://docs.microsoft.com/en-us/windows/desktop/debug/retrieving-the-last-error-code
    #

    dw = GetLastError()
    errmsg = ""

    if dw != 0:
        # use FormatMessageW with FORMAT_MESSAGE_IGNORE_INSERTS
        flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS

        msgbuffer = NULL
        FormatMessageW(flags,
                       NULL,
                       dw,
                       MAKELANGID(LANG_USER_DEFAULT, SUBLANG_DEFAULT),
                       <LPWSTR>&msgbuffer,
                       0,
                       NULL)

        try:
            # decode to unicode string, assuming UTF-16 LE encoding
            errmsg = <unicode>msgbuffer
        finally:
            # free memory even if decoding fails
            LocalFree(msgbuffer)

        if so is not None:
            # encode so to a unicode string before substitution
            so_bytes = so.encode("utf-8")
            # substitute '%1'
            errmsg = errmsg.replace(u"%1", so_bytes.decode("utf-8"))

    return errmsg

#EOF
