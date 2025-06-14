#define PY_SSIZE_T_CLEAN
#include <Python.h>

#ifdef _WIN32
#include "Windows.h"
typedef HINSTANCE LIB_HANDLE;
#else
#include <dlfcn.h>
typedef void *LIB_HANDLE;
#endif

#ifndef P11_HANDLE
typedef struct P11_HANDLE {
    LIB_HANDLE lib_handle;
    void * get_function_list_ptr;
} P11_HANDLE;
#endif

static PyObject* p11_error();
static P11_HANDLE* p11_open(PyObject *path_str);
static int p11_close(P11_HANDLE* handle);
