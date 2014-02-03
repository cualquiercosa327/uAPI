#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base64.h"
#include "haywire.h"

#define CRLF "\r\n"

/* Executes after sending the response to the client. */
static void
response_complete(void *user_data)
{
}

/* Returns a 1 if a username and password could be parsed, otherwise
 * a 0 is returned. */
static int
parse_authorization(http_request *request, char *username, size_t sz_user,
    char *password, size_t sz_pass)
{
	char *auth_header;
	char base64dec[1024]; /* Contains username, password, 1024 should be ok! */
	size_t sz_base64dec;
	char *p_colon;

	/* All HTTP headers are stored in lowercase. */
	auth_header = hw_get_header(request, "authorization");
	if (!auth_header)
		return 0;

	/* We next determine the type of authorization, however at this time only
	 * Basic is supported. */
	if (strncmp(auth_header, "Basic", 5)) {
		return 0;
	}

	/* Advance "Basic " characters. */
	sz_base64dec = sizeof(base64dec);
	if (base64decode(auth_header + 6, strlen(auth_header + 6),
	    (unsigned char *)base64dec, &sz_base64dec)) {
		/* An error occurred decoding the auth_header, return error. */
		return 0;
	}

	base64dec[sz_base64dec] = '\0';
	p_colon = strchr(base64dec, ':');
	if (!p_colon) {
		/* Invalid header */
		return 0;
	}

	*p_colon = '\0';
	snprintf(username, sz_user, "%s", base64dec);
	snprintf(password, sz_pass, "%s", p_colon + 1);
	return 1;
}

static void
send_response(http_request *request, hw_http_response *response,
    void *user_data)
{
	hw_string keep_alive_name;
	hw_string keep_alive_value;

	if (request->keep_alive) {
		SETSTRING(keep_alive_name, "Connection");

		SETSTRING(keep_alive_value, "Keep-Alive");
		hw_set_response_header(response, &keep_alive_name, &keep_alive_value);
	} else {
		hw_set_http_version(response, 1, 0);
	}

	hw_http_response_send(response, "user_data", response_complete);
}

static void
authenticate(http_request *request, hw_http_response *response, void *user_data)
{
	hw_string status_code;
	hw_string content_type_name;
	hw_string content_type_value;
	hw_string body;
	char username[512];
	char password[512];

	if (!parse_authorization(request, username, sizeof(username), password,
	    sizeof(password))) {
		SETSTRING(status_code, HTTP_STATUS_401);
		hw_set_response_status_code(response, &status_code);

		SETSTRING(content_type_name, "Content-Type");
		SETSTRING(content_type_value, "application/json");
		hw_set_response_header(response, &content_type_name, &content_type_value);
		SETSTRING(body, "{\"ErrorCode\":0,\"ErrorMessage\":\"Invalid username "
		    "or password.\"}");;
		hw_set_body(response, &body);
	} else {
//		fprintf(stderr, "user: %s, pass: %s\n", username, password);

		/* For now, return status 200 if the user has basic auth, but in the future
		 * we need to actually validate username/password */
		SETSTRING(status_code, HTTP_STATUS_200);
		hw_set_response_status_code(response, &status_code);
	}

	send_response(request, response, user_data);
}

static void
get_root(http_request *request, hw_http_response *response, void *user_data)
{
	hw_string status_code;
	hw_string content_type_name;
	hw_string content_type_value;
	hw_string body;

	SETSTRING(status_code, HTTP_STATUS_200);
	hw_set_response_status_code(response, &status_code);

	SETSTRING(content_type_name, "Content-Type");

	SETSTRING(content_type_value, "text/html");
	hw_set_response_header(response, &content_type_name, &content_type_value);

	SETSTRING(body, "hello world");
	hw_set_body(response, &body);

	send_response(request, response, user_data);
}

int
main(int args, char **argsv)
{
	char route[] = "/";
	configuration config;

	config.http_listen_address = "0.0.0.0";

	if (args > 1) {
		config.http_listen_port = atoi(argsv[1]);
	} else {
		config.http_listen_port = 8000;
	}

	/* hw_init_from_config("hello_world.conf"); */
	hw_init_with_config(&config);
	hw_http_add_route(route, get_root, NULL);
	hw_http_add_route("/Authenticate", authenticate, NULL);

	hw_http_open(0);
	return 0;
}

