#ifndef __HW_HTTP_REQUEST_CACHE_H__
#define __HW_HTTP_REQUEST_CACHE_H__

#include "haywire.h"
#include "uv.h"

void initialize_http_request_cache();
hw_string* get_cached_request(char* http_status);

#endif /* _HW_HTTP_REQUEST_CACHE_H__ */
