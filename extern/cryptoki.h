#ifndef _CRYPTOKI_H_
#define _CRYPTOKI_H_ 1

#ifdef __cplusplus
extern "C" {
#endif


#if defined(__CYGWIN64__)
#pragma warning "Cygwin 64 bits will only work with Cygwin-compiled PKCS#11 modules"
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

