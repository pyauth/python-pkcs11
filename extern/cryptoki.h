#ifndef _CRYPTOKI_H_
#define _CRYPTOKI_H_ 1

/* MIT License */

/* Copyright (c) 2019 Eric Devolder */

/* Permission is hereby granted, free of charge, to any person obtaining  */
/* a copy of this software and associated documentation files (the        */
/* "Software"), to deal in the Software without restriction, including    */
/* without limitation the rights to use, copy, modify, merge, publish,    */
/* distribute, sublicense, and/or sell copies of the Software, and to     */
/* permit persons to whom the Software is furnished to do so, subject to  */
/* the following conditions:                                              */

/* The above copyright notice and this permission notice shall be         */
/* included in all copies or substantial portions of the Software.        */

/* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,        */
/* EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF     */
/* MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND                  */
/* NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE */
/* LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION */
/* OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION  */
/* WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.        */


#ifdef __cplusplus
extern "C" {
#endif

#if defined(__CYGWIN64__)
#pragma warning "Cygwin 64 bits build will only work with Cygwin64-compiled PKCS#11 modules"
#endif

#define CK_PTR            *
#define CK_DEFINE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)

#ifndef NULL_PTR
#define NULL_PTR          0
#endif

#if defined(_MSC_VER) && defined(_WIN32) /* we are compiling using Visual C */
#pragma pack(push, cryptoki, 1)
#elif defined(__CYGWIN__)
#pragma pack(push, 1)
#endif

#include "pkcs11.h"

#if defined(_MSC_VER) && defined(_WIN32) /* we are compiling using Visual C */
#pragma pack(pop, cryptoki)
#elif defined(__CYGWIN__)
#pragma pack(pop)
#endif

#ifdef __cplusplus
}
#endif

#endif /* _CRYPTOKI_H_ */

