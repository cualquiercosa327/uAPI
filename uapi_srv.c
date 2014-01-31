#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uv.h>
//#include "haywire.h"

uv_loop_t *loop; /* Main event loop */

int round_robin_counter;
int child_worker_count;

struct child_worker {
	uv_process_t req;
	uv_process_options_t options;
	uv_pipe_t pipe;
} *workers;

static void
close_process_handle(uv_process_t *req, int64_t exit_status, int term_signal)
{
	fprintf(stderr, "Process exited with status %d, signal %d\n",
	    (int)exit_status, term_signal);
	uv_close((uv_handle_t *)req, NULL);
}

static void
spawn_processors(void)
{
	char processor_path[500];
	size_t path_size = sizeof(processor_path);
	char *p;
	char *args[2];
	int cpu_count;
	uv_cpu_info_t *info;

	/* uv_exepath determines the full path (containing the executable) of the
	 * currently running process. */
	uv_exepath(processor_path, &path_size);

	/* We make the assumption here that our processors are in the same
	 * directory. */

	/* Locate the last directory character, terminate the string 1 char after,
	 * and slap on the uapi_proc executable */
	fprintf(stderr, "Service path: %s\n", processor_path);
#ifdef WIN32
	p = strrchr(processor_path, '\\');
#else
	p = strrchr(processor_path, '/');
#endif
	if (p) {
		p[1] = '\0';
#ifdef WIN32
		strncat(processor_path, "uapi_proc.exe",
		    sizeof(processor_path) - 1 - strlen("uapi_proc.exe"));
#else
		strncat(processor_path, "uapi_proc",
		    sizeof(processor_path) - 1 - strlen("uapi_proc"));
#endif
	}
	fprintf(stderr, "Worker path: %s\n", processor_path);

	/* Setup argv for spawned processors */
	args[0] = processor_path;
	args[1] = NULL; /* no arguments to executable */

	round_robin_counter = 0;

	/* launch same number of workers as number of CPUs */
	uv_cpu_info(&info, &cpu_count);
	uv_free_cpu_info(info, cpu_count);

	child_worker_count = cpu_count;

	workers = calloc(sizeof(struct child_worker), cpu_count);
	while (cpu_count--) {
		struct child_worker *worker = &workers[cpu_count];

		uv_pipe_init(loop, &worker->pipe, 1);

		uv_stdio_container_t child_stdio[3];
		child_stdio[0].flags = UV_CREATE_PIPE | UV_READABLE_PIPE;
		child_stdio[0].data.stream = (uv_stream_t*) &worker->pipe;
		child_stdio[1].flags = UV_IGNORE;
		child_stdio[2].flags = UV_INHERIT_FD;
		child_stdio[2].data.fd = 2;

		worker->options.stdio = child_stdio;
		worker->options.stdio_count = 3;

		worker->options.exit_cb = close_process_handle;
		worker->options.file = args[0];
		worker->options.args = args;

		uv_spawn(loop, &worker->req, &worker->options); 
		fprintf(stderr, "Started worker %d\n", worker->req.pid);
	}
}

static void
on_new_connection(uv_stream_t *server, int status)
{
	if (status == -1) {
		// error!
		return;
	}

	uv_tcp_t *client = (uv_tcp_t *) malloc(sizeof(uv_tcp_t));
	uv_tcp_init(loop, client);

	if (uv_accept(server, (uv_stream_t*) client) == 0) {
		uv_buf_t dummy_buf;
		uv_write_t *write_req = (uv_write_t*) malloc(sizeof(uv_write_t));
		dummy_buf = uv_buf_init(".", 1);
		/* Send accepted TCP socket over pipe. */
		struct child_worker *worker = &workers[round_robin_counter];
		uv_write2(write_req, (uv_stream_t*) &worker->pipe, &dummy_buf, 1, (uv_stream_t*) client, NULL);
		round_robin_counter = (round_robin_counter + 1) % child_worker_count;
	}
	/* The handle is duplicated when it's sent to the child process and we don't
	 * need to use it here, so close it */
	uv_close((uv_handle_t*) client, NULL);
}

/* Process configuration a bit better */
int
main(int args, char **argsv)
{
	struct sockaddr_in listen_address;
	uv_tcp_t server;

	/* TODO: Handle arguments / configuration files */
	loop = uv_default_loop();

	spawn_processors();

	uv_tcp_init(loop, &server);
	uv_ip4_addr("0.0.0.0", 8000, &listen_address);

	uv_tcp_bind(&server, (const struct sockaddr *)&listen_address, 0);
	if (uv_listen((uv_stream_t*) &server, 128, on_new_connection)) {
		fprintf(stderr, "uv_listen: Error couldn't listen\n");
		return 2;
	}

	return uv_run(loop, UV_RUN_DEFAULT);


	/*
	configuration config;

	config.http_listen_address = "0.0.0.0";

	if (args > 1) {
		config.http_listen_port = atoi(argsv[1]);
	} else {
		config.http_listen_port = 8000;
	}
	*/

	/* hw_init_from_config("hello_world.conf"); */
	//hw_init_with_config(&config);

	/* Determine number of CPUs for scaling purposes */

//	hw_http_open(0);
	return 0;
}

