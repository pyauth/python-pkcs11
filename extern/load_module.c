#define PY_SSIZE_T_CLEAN
#include "load_module.h"


#ifdef _WIN32
static PyObject* p11_error() {
    DWORD dwMessageId = GetLastError();
    LPWSTR msgbuffer = NULL;

    if (dwMessageId != 0) {
        DWORD l = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER|FORMAT_MESSAGE_FROM_SYSTEM|FORMAT_MESSAGE_IGNORE_INSERTS,
                    NULL,
                    dwMessageId,
                    MAKELANGID(LANG_USER_DEFAULT, SUBLANG_DEFAULT),
                    (LPWSTR) &msgbuffer,
                    0,
                    NULL);
        PyObject* errmsg = PyUnicode_FromWideChar(msgbuffer, l);
        LocalFree(msgbuffer);
        if (errmsg == NULL) {
            Py_RETURN_NONE;
        }
        return errmsg;
    } else {
        Py_RETURN_NONE;
    }
}

static P11_HANDLE* p11_open(PyObject *path_str) {
    wchar_t *path = PyUnicode_AsWideCharString(path_str, NULL);
    LIB_HANDLE handle = LoadLibraryW(path);
    PyMem_Free(path);

    P11_HANDLE* result = NULL;
    if (handle != NULL) {
        void * ptr = GetProcAddress(handle, "C_GetFunctionList");
        if (ptr != NULL) {
             result = (P11_HANDLE*) PyMem_Malloc(sizeof(P11_HANDLE));
             result->lib_handle = handle;
             result->get_function_list_ptr = ptr;
        }
    }
    return result;
}

static int p11_close(P11_HANDLE* handle) {
    if(handle != NULL) {
        LIB_HANDLE lib_handle = handle->lib_handle;
        PyMem_Free(handle);
        if (lib_handle != NULL) {
            return FreeLibrary(lib_handle);
        }
    }
    return 0;
}

#else

static PyObject* p11_error() {
    char* error = dlerror();

    if (error == NULL) {
        Py_RETURN_NONE;
    }
    int len = strlen(error);
    PyObject* result = PyUnicode_DecodeUTF8(error, len, NULL);
    if (result == NULL) {
        Py_RETURN_NONE;
    }
    return result;
}

static P11_HANDLE* p11_open(PyObject *path_str) {
    const char *path = PyUnicode_AsUTF8AndSize(path_str, NULL);
    // Note: python manages this buffer, no need to deallocate it here


    P11_HANDLE* result = NULL;

    LIB_HANDLE handle = dlopen(path, RTLD_LAZY | RTLD_LOCAL);

    if (handle != NULL) {
        void * ptr = dlsym(handle, "C_GetFunctionList");
        if (ptr != NULL) {
             result = (P11_HANDLE*) PyMem_Malloc(sizeof(P11_HANDLE));
             result->lib_handle = handle;
             result->get_function_list_ptr = ptr;
        }
    }
    return result;
}

static int p11_close(P11_HANDLE* handle) {
    if(handle != NULL) {
        LIB_HANDLE lib_handle = handle->lib_handle;
        PyMem_Free(handle);
        if (lib_handle != NULL) {
            return dlclose(lib_handle);
        }
    }
    return 0;
}

#endif