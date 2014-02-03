#ifndef __HW_HTTP_REQUEST_H__
#define __HW_HTTP_REQUEST_H__

#include "uv.h"
#include "http_parser.h"

extern int last_was_value;

void print_headers(http_request* request);
void free_http_request(http_request* request);
int http_request_on_message_begin(http_parser *parser);
int http_request_on_url(http_parser *parser, const char *at, size_t length);
int http_request_on_header_field(http_parser *parser, const char *at, size_t length);
int http_request_on_header_value(http_parser *parser, const char *at, size_t length);
int http_request_on_body(http_parser *parser, const char *at, size_t length);
int http_request_on_headers_complete(http_parser *parser);
int http_request_on_message_complete(http_parser *parser);

#endif /* __HW_HTTP_REQUEST_H__ */
