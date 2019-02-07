#ifndef _CRYPTOKI_H_
#define _CRYPTOKI_H_ 1

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_MSC_VER) && defined(_WIN32) /* we are compiling using Visual C */
#pragma pack(push, cryptoki, 1)
#endif

#include "pkcs11.h"

#if defined(_MSC_VER) && defined(_WIN32) /* we are compiling using Visual C */
#pragma pack(pop, cryptoki)
#endif

#ifdef __cplusplus
}
#endif

#endif /* _CRYPTOKI_H_ */

