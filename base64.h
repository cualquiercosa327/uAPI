/* The uAPI Base64 decoder.
 * This code is from the public domain and the auther is unknown. */

#ifndef __UAPI_BASE64_H__
#define __UAPI_BASE64_H__

#include <stddef.h>

int base64decode (char *in, size_t inLen, unsigned char *out, size_t *outLen);

#endif /* __UAPI_BASE64_H__ */
