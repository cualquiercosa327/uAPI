#ifdef PLATFORM_POSIX
#include <signal.h>
#endif // PLATFORM_POSIX

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "uv.h"
#include "haywire.h"
#include "hw_string.h"
#include "khash.h"
#include "http_server.h"
#include "http_request.h"
#include "http_parser.h"
#include "http_connection.h"
#include "http_response_cache.h"
#include "server_stats.h"
#include "route_compare_method.h"
#include "configuration/configuration.h"

#define UVERR(err, msg) fprintf(stderr, "%s: %s\n", msg, uv_strerror(err))
#define CHECK(r, msg) \
if (r) { \
uv_err_t err = uv_last_error(uv_loop); \
UVERR(err, msg); \
exit(1); \
}

/* Create a hash map with a value of hw_route_entry* */
KHASH_MAP_INIT_STR(string_hashmap, hw_route_entry*)

static configuration* config;
static uv_tcp_t server;
static http_parser_settings parser_settings;

uv_loop_t* uv_loop;
uv_pipe_t queue;

void* routes;
hw_string* http_v1_0;
hw_string* http_v1_1;
hw_string* server_name;
int listener_count;
uv_async_t* listener_async_handles;
uv_loop_t* listener_event_loops;
uv_barrier_t* listeners_created_barrier;

http_connection* create_http_connection()
{
    http_connection* connection = malloc(sizeof(http_connection));
    connection->request = NULL;
    INCREMENT_STAT(stat_connections_created_total);
    return connection;
}

void free_http_connection(http_connection* connection)
{
    if (connection->request != NULL)
    {
        free_http_request(connection->request);
    }
    
    free(connection);
    INCREMENT_STAT(stat_connections_destroyed_total);
}

void set_route(void* hashmap, char* name, hw_route_entry* route_entry)
{
    int ret;
    khiter_t k;
    khash_t(string_hashmap) *h = hashmap;
    k = kh_put(string_hashmap, h, strdup(name), &ret);
    kh_value(h, k) = route_entry;
}

void hw_http_add_route(char *route, http_request_callback callback, void* user_data)
{
    hw_route_entry* route_entry = malloc(sizeof(hw_route_entry));
    route_entry->callback = callback;
    route_entry->user_data = user_data;
    
    if (routes == NULL)
    {
        routes = kh_init(string_hashmap);
    }
    set_route(routes, route, route_entry);
}

int hw_init_from_config(char* configuration_filename)
{
    configuration* config = load_configuration(configuration_filename);
    if (config == NULL)
    {
        return 1;
    }
    return hw_init_with_config(config);
}

int hw_init_with_config(configuration* c)
{
#ifdef DEBUG
    char route[] = "/stats";
    hw_http_add_route(route, get_server_stats, NULL);
#endif /* DEBUG */
    /* Copy the configuration */
    config = malloc(sizeof(configuration));
    config->http_listen_address = strdup(c->http_listen_address);
    config->http_listen_port = c->http_listen_port;
    
    http_v1_0 = create_string("HTTP/1.0 ");
    http_v1_1 = create_string("HTTP/1.1 ");
    server_name = create_string("Server: Haywire/master");
    return 0;
}

void free_http_server()
{
    /* TODO: Shut down accepting incoming requests */
    khash_t(string_hashmap) *h = routes;
	/* TODO: XXX does k need to be const here ? */
    const char* k;
    hw_route_entry* v;
    kh_foreach(h, k, v, { free((char *)k); free(v); });
    kh_destroy(string_hashmap, routes);
}

void
http_stream_on_alloc(uv_handle_t* client, size_t suggested_size, uv_buf_t* buf)
{
	buf->base = malloc(suggested_size);
	buf->len = suggested_size;
}

void
on_http_new_connection(uv_pipe_t *q, ssize_t nread, const uv_buf_t *buf,
    uv_handle_type pending)
{
	if (pending == UV_UNKNOWN_HANDLE) {
		/* Error condition! */
		return;
	}

	http_connection* connection = create_http_connection();
	uv_tcp_init(uv_loop, &connection->stream);
	http_parser_init(&connection->parser, HTTP_REQUEST);

	connection->parser.data = connection;
	connection->stream.data = connection;

	/* TODO: Use the return values from uv_accept() and uv_read_start() */
	if (uv_accept((uv_stream_t *)q, (uv_stream_t*)&connection->stream) == 0) {
		uv_read_start((uv_stream_t*)&connection->stream, http_stream_on_alloc, http_stream_on_read);
	}

	/* TODO: Close client if accept fails? */

}

/* Main call to haywire */
int hw_http_open(int debug)
{
	/* Setup callbacks for the HTTP parser. */
	/* It comes out of https://github.com/joyent/http-parser */
	parser_settings.on_header_field = http_request_on_header_field;
	parser_settings.on_header_value = http_request_on_header_value;
	parser_settings.on_headers_complete = http_request_on_headers_complete;
	parser_settings.on_body = http_request_on_body;
	parser_settings.on_message_begin = http_request_on_message_begin;
	parser_settings.on_message_complete = http_request_on_message_complete;
	parser_settings.on_url = http_request_on_url;

#ifdef PLATFORM_POSIX
	signal(SIGPIPE, SIG_IGN);
#endif // PLATFORM_POSIX


	/* TODO: Use the return values from uv_tcp_init() and uv_tcp_bind() */
	uv_loop = uv_default_loop();
	uv_tcp_init(uv_loop, &server);

	listener_async_handles = calloc(0, sizeof(uv_async_t));
	listener_event_loops = calloc(0, sizeof(uv_loop_t));

	/* Setup a barrier to wait for all threads to create listeners. The main
	 * thread also waits (hence the +1). */
	listeners_created_barrier = malloc(sizeof(uv_barrier_t));
	uv_barrier_init(listeners_created_barrier, 1);

	/*
	 * async handler that's never used?  */
#if 0
    uv_async_t* service_handle = malloc(sizeof(uv_async_t));
    uv_async_init(uv_loop, service_handle, NULL);
#endif

		/* If running single threaded there is no need to use the IPC pipe
		 to distribute requests between threads so lets avoid the IPC overhead */

		initialize_http_request_cache();

		if (!debug) {
			uv_pipe_init(uv_loop, &queue, 1);
			uv_pipe_open(&queue, 0);

			uv_read2_start((uv_stream_t *)&queue, http_stream_on_alloc,
			    on_http_new_connection);
		} else {
			struct sockaddr_in listen_address;
			uv_ip4_addr("0.0.0.0", 8000, &listen_address);
			uv_tcp_bind(&server, (const struct sockaddr*)&listen_address, 0);
			uv_listen((uv_stream_t*)&server, 128, http_stream_on_connect);
			printf("Listening on %s:%d\n", config->http_listen_address, config->http_listen_port);
		}

	uv_run(uv_loop, UV_RUN_DEFAULT);

	return 0;
}

void http_stream_on_connect(uv_stream_t* stream, int status)
{
    http_connection* connection = create_http_connection();
    uv_tcp_init(uv_loop, &connection->stream);
    http_parser_init(&connection->parser, HTTP_REQUEST);
    
    connection->parser.data = connection;
    connection->stream.data = connection;
    
    /* TODO: Use the return values from uv_accept() and uv_read_start() */
    uv_accept(stream, (uv_stream_t*)&connection->stream);
    uv_read_start((uv_stream_t*)&connection->stream, http_stream_on_alloc, http_stream_on_read);
}


/* Fired when uv_close finishes executing. Responsible for freeing the
 * http_connection. */
static void
http_stream_on_close(uv_handle_t *handle)
{
	http_connection* connection = (http_connection*)handle->data;
	free_http_connection(connection);
}

/* http_stream_on_read is the default read callback on our streaming
 * connection. */
void
http_stream_on_read(uv_stream_t* tcp, ssize_t nread, const uv_buf_t* buf)
{
	ssize_t parsed;
	http_connection* connection = (http_connection*)tcp->data;

	if (nread < 0) {

		/* Error or EOF */
		if (buf->base) {
			free(buf->base);
		}

		uv_close((uv_handle_t*) &connection->stream, http_stream_on_close);
		return;
	}

	if (nread == 0) {
		/* Everything OK, but nothing read. */
		free(buf->base);
		return;
	}

	/* Parse nread bytes of the buf->base string.
	 * TODO: Possibly support EOF (nread value 0) in the parser? */
	parsed = http_parser_execute(&connection->parser, &parser_settings,
	    buf->base, nread);

	if (connection->parser.upgrade) {
		/* handle new protocol */
		fprintf(stderr, "TODO: handle upgrade error?\n");
	} else if (parsed != nread) {
		/* Handle error. Usually just close the connection. */
		fprintf(stderr, "parser error!\n");
	}

	free(buf->base);
}

/* This function is called after uv_write completes */
static void
http_server_after_write(uv_write_t* req, int status)
{
	hw_write_context* write_context = (hw_write_context*)req->data;
	uv_buf_t *resbuf = (uv_buf_t *)(req+1);

	if (!write_context->connection->keep_alive) {
		uv_close((uv_handle_t*)req->handle, http_stream_on_close);
	}

	if (write_context->callback != 0) {
		write_context->callback(write_context->user_data);
	}

	free(write_context);
	free(resbuf->base);
	free(req);
}

int
http_server_write_response(hw_write_context* write_context, hw_string* response)
{
	uv_write_t* write_req = (uv_write_t *)malloc(sizeof(*write_req) + sizeof(uv_buf_t));
	uv_buf_t* resbuf = (uv_buf_t *)(write_req+1);

	resbuf->base = response->value;
	resbuf->len = response->length + 1;

	write_req->data = write_context;

	/* TODO: Use the return values from uv_write() */
	uv_write(write_req, (uv_stream_t *)&write_context->connection->stream,
	    resbuf, 1, http_server_after_write);
	return 0;
}

