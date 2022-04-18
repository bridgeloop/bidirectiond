#include "core_settings.h"
#include "cp_pwd.h"
#include "input_processor.h"
#include "strtoint.h"
#include "tls_put.h"

#include <arpa/inet.h>
#include <bddc/api.h>
#include <fcntl.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <pwd.h>
#include <signal.h>
#include <sys/resource.h>
#include <sys/signalfd.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#ifndef BIDIRECTIOND_USERNAME
#define BIDIRECTIOND_USERNAME "nobody"
#endif

#if CHAR_BIT != 8
#error The target architecture is unsupported
#endif

struct bdd_settings settings = {
	.name_descriptions = NULL,
	.n_connections = 0x100,
	.n_epoll_oevents = 0x200,
	.buf_sz = 0x800,
	.n_worker_threads = 16,
	.client_timeout = 12000,
	.use_stack_buf = false,
	.sv_socket = -1,
	.use_work_queues = false,
};

#define PASTE(x, y) x##y
#define sto(w, t) \
	void PASTE(sto, w)(t * dest, char *str) { \
		signed long long int v; \
		if (!bdd_strtosll(str, strlen(str), &(v))) { \
			return; \
		} \
		if (v == (t)v) { \
			*dest = (t)v; \
		} \
		return; \
	}
sto(i, int);
sto(ui, unsigned int);
sto(usi, unsigned short int);
sto(uid, uid_t);
sto(gid, gid_t);
sto(sz, size_t);
void storlim(rlim_t *dest, char *str) {
	unsigned long long int v;
	if (!bdd_strtoull(str, strlen(str), &(v))) {
		return;
	}
	if (v == (rlim_t)v) {
		(*dest) = (rlim_t)v;
	}
	return;
}

// main
#ifndef HASHMAP_MAIN
int main(int argc, char *argv[], char *env[]) {
	puts("bidirectiond version " PROG_SEMVER);
	// set up tls
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
	ERR_load_BIO_strings();
	ERR_load_crypto_strings();

	struct bdd_instance *bdd_instance = NULL;
	int input_fd = -1;
	struct sockaddr_un input_addr = {
		0,
		.sun_family = AF_UNIX,
	};
	int sig_fd = -1;

	// name_descriptions
	if ((settings.name_descriptions = hashmap_create((void (*)(void *)) & (bdd_name_description_destroy))) == NULL) {
		fputs("failed to allocate settings.name_descriptions\n", stderr);
		goto main__clean_up;
	}
	// args
	char **arg = &(argv[1]);
	if (argc < 1 /* linux */) {
		arg = argv;
	}
	bool disable_ipv6 = false;
	int backlog = 0;
	unsigned short int port = 443;

	// the uid of the current user
	/* for example:
		nuid will contain the uid that the program was started by,
		even if bidirectiond is setuid.
		nuid will be used later to restore a safe uid, if the process
		becomes (or already is) root. */
	uid_t nuid = getuid();
	uid_t ngid = getgid();

	setpwent();
	for (struct passwd *pw = getpwent(); pw != NULL; pw = getpwent()) {
		if (strcmp(pw->pw_name, BIDIRECTIOND_USERNAME) == 0) {
#ifdef BIDIRECTIOND_SU
			nuid = pw->pw_uid;
			ngid = pw->pw_gid;
#else
			if (nuid == 0) {
				nuid = pw->pw_uid;
			}
			if (ngid == 0) {
				ngid = pw->pw_gid;
			}
#endif
			break;
		}
	}
	endpwent();

	struct locked_hashmap *lh = hashmap_lock(settings.name_descriptions);
	size_t big_alloc_sz = 0;

#define EXPECT_ARGS(n) \
	for (size_t idx = 1; idx <= n; ++idx) { \
		if (arg[idx] == NULL || arg[idx][0] == '-') { \
			goto main__arg_fuck; \
		} \
	}
main__arg_iter:;
	while ((*arg) != NULL) {
		if (strcmp((*arg), "--n-connection-threads") == 0 || strcmp((*arg), "-t") == 0) {
			EXPECT_ARGS(1);
			stousi(&(settings.n_worker_threads), arg[1]);
			arg += 2;
		} else if (strcmp((*arg), "--client-timeout") == 0) {
			EXPECT_ARGS(1);
			stoui(&(settings.client_timeout), arg[1]);
			arg += 2;
		} else if (strcmp((*arg), "-l") == 0) {
			EXPECT_ARGS(2);
			struct rlimit rlimit;
			storlim(&(rlimit.rlim_cur), arg[1]);
			storlim(&(rlimit.rlim_max), arg[2]);
			if (setrlimit(RLIMIT_NOFILE, &(rlimit)) != 0) {
				fputs("setrlimit failed\n", stderr);
			}
			arg += 3;
		} else if (strcmp((*arg), "--buffer-size") == 0 || strcmp((*arg), "-b") == 0) {
			EXPECT_ARGS(1);
			stoui(&(settings.buf_sz), arg[1]);
			arg += 2;
		} else if (strcmp((*arg), "--backlog") == 0) {
			EXPECT_ARGS(1);
			stoi(&(backlog), arg[1]);
			arg += 2;
		} else if (strcmp((*arg), "--server-tcp-port") == 0 || strcmp((*arg), "-p") == 0) {
			EXPECT_ARGS(1);
			stousi(&(port), arg[1]);
			arg += 2;
		} else if (strcmp((*arg), "--max-connections") == 0) {
			EXPECT_ARGS(1);
			stoi(&(settings.n_connections), arg[1]);
			arg += 2;
		} else if (strcmp((*arg), "--disable-ipv6") == 0) {
			disable_ipv6 = true;
			arg += 1;
		} else if (strcmp((*arg), "--use-work-queue") == 0) {
			settings.use_work_queues = true;
			arg += 1;
		} else if (strcmp((*arg), "--nohup") == 0) {
			struct sigaction action = {
				.sa_handler = SIG_IGN,
				.sa_flags = SA_RESTART,
			};
			sigaction(SIGHUP, &(action), 0);
			arg += 1;
		} else if (strcmp((*arg), "--tls-credentials") == 0 || strcmp((*arg), "-c") == 0) {
			EXPECT_ARGS(3);
			SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
			if (SSL_CTX_use_certificate_file(ctx, arg[1], SSL_FILETYPE_PEM) != 1) {
				fputs("invalid certificate file\n", stderr);
				goto main__arg_creds_err;
			}
			struct bdd_cp_ctx cp_ctx = {
				.success = false,
				.password = getenv(arg[3]),
			};
			SSL_CTX_set_default_passwd_cb(ctx, bdd_cp_pwd);
			SSL_CTX_set_default_passwd_cb_userdata(ctx, &(cp_ctx));
			if (SSL_CTX_use_PrivateKey_file(ctx, arg[2], SSL_FILETYPE_PEM) != 1) {
				fputs("invalid private key file\n", stderr);
				goto main__arg_creds_err;
			}
			if (!cp_ctx.success) {
				fputs("the private key file must be encrypted\n", stderr);
				goto main__arg_creds_err;
			}
			SSL_CTX_set_ecdh_auto(ctx, 1);
			if (SSL_CTX_set_cipher_list(ctx, "HIGH:!aNULL:!MD5") != 1) {
				fputs("failed to set the ssl_ctx's cipher list\n", stderr);
				goto main__arg_creds_err;
			}
			SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);
			SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION);
			if (!tls_put(lh, &(ctx))) {
				fputs("seemingly invalid certificate file\n", stderr);
				goto main__arg_creds_err;
			}
main__arg_creds_err:;
			if (ctx != NULL) {
				SSL_CTX_free(ctx);
			}
			arg += 4;
		} else if (strcmp((*arg), "--UNSAFE allocate buffer on stack") == 0) {
			fputs("'--UNSAFE allocate buffer on stack' is unsafe and "
			      "shouldn't be used\n",
			      stderr);
			settings.use_stack_buf = true;
			arg += 1;
		} else if (getuid() == 0 && strcmp((*arg), "--uid") == 0) {
			EXPECT_ARGS(1);
			stouid(&(nuid), arg[1]);
			arg += 2;
		} else if (getgid() == 0 && strcmp((*arg), "--gid") == 0) {
			EXPECT_ARGS(1);
			stogid(&(ngid), arg[1]);
			arg += 2;
		} else if (strcmp((*arg), "--n-epoll-oevents") == 0) {
			EXPECT_ARGS(1);
			stoi(&(settings.n_epoll_oevents), arg[1]);
			arg += 2;
		} else if (strcmp((*arg), "--input") == 0) {
			EXPECT_ARGS(1);
			size_t str_len = strlen(arg[1]);
			if (str_len == 0 || str_len >= sizeof(input_addr.sun_path)) {
				fputs("--input path is of invalid length\n", stderr);
			} else if (input_addr.sun_path[0] != 0) {
				fputs("cannot specify --input twice\n", stderr);
			} else {
				strcpy(input_addr.sun_path, arg[1]);
			}
			arg += 2;
		} else if (strcmp((*arg), "--big-alloc") == 0) {
			EXPECT_ARGS(1);
			stosz(&(big_alloc_sz), arg[1]);
			arg += 2;
		} else {
			for (size_t idx = 0; idx < N_INTERNAL_SERVICES; ++idx) {
				if (internal_services[idx].supported_arguments != NULL)
					for (size_t pidx = 0; internal_services[idx].supported_arguments[pidx]; ++pidx) {
						if (strcmp((*arg), internal_services[idx].supported_arguments[pidx]) == 0) {
							size_t n = 1;
							while (arg[n] != NULL && (arg[n][0] != '-' || (arg[n][1] >= '0' && arg[n][1] <= '9'))) {
								n += 1;
							}
							if (!internal_services[idx].service_init(lh, &(internal_services[idx]), n, arg)) {
								goto main__arg_fuck;
							}
							arg = &(arg[n]);
							goto main__arg_iter;
						}
					}
			}
main__arg_fuck:;
			puts("argument parsing failed\n"
			     "-t: set the amount of worker threads\n"
			     "--client-timeout: set the timeout (in ms) for "
			     "client socket i/o\n"
			     "-l: set the rlimits for open files (soft limit, "
			     "hard limit)\n"
			     "-b: set the size of the large worker buffers\n"
			     "--backlog: set the tcp backlog for sv_socket\n"
			     "-p: set the tcp port to bind sv_socket to\n"
			     "--max-connections: the max amount of "
			     "bdd_connections structs\n"
			     "--disable-ipv6: sv_socket should not use ipv6\n"
			     "--use-work-queue: do not wait for worker threads "
			     "before giving them work\n"
			     "--nohup: SIG_IGN SIGHUP\n"
			     "-c: load pem-encoded tls credentials (e.g. `-c "
			     "cert.pem encrypted-key.pem "
			     "name-of-password-environment-variable`)\n"
			     "--input: set the path for a udp unix socket, so "
			     "that some bidirectiond settings can be modified "
			     "without restarting\n"
			     "--n-epoll-oevents: epoll_wait maxevents\n"
			     "--big-alloc: reserve some ram");
			for (size_t idx = 0; idx < N_INTERNAL_SERVICES; ++idx) {
				if (internal_services[idx].arguments_help != NULL) {
					fputs(internal_services[idx].arguments_help, stdout);
				}
			}
			locked_hashmap_unlock(&(lh));
			goto main__clean_up;
		}
	}
	locked_hashmap_unlock(&(lh));

	// potentially a setuid program
	if (getuid() != 0 && geteuid() == 0) {
		setuid(0);
	}

	// set up socket
	union {
		struct sockaddr_in inet4;
		struct sockaddr_in6 inet6;
	} sv_addr = {
		0,
	};
	size_t sv_addr_sz = 0;
	if (disable_ipv6) {
		settings.sv_socket = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
		sv_addr_sz = sizeof(struct sockaddr_in);
		sv_addr.inet4.sin_family = AF_INET;
		sv_addr.inet4.sin_addr.s_addr = INADDR_ANY;
		sv_addr.inet4.sin_port = htons(port);
	} else {
		settings.sv_socket = socket(AF_INET6, SOCK_STREAM | SOCK_NONBLOCK, 0);
		sv_addr_sz = sizeof(struct sockaddr_in6);
		sv_addr.inet6.sin6_family = AF_INET6;
		sv_addr.inet6.sin6_addr = in6addr_any;
		sv_addr.inet6.sin6_port = htons(port);
	}
	// try to bind to port
	int opt = 1;
	setsockopt(settings.sv_socket, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &(opt), sizeof(opt));
	if (bind(settings.sv_socket, (struct sockaddr *)&(sv_addr), sv_addr_sz) < 0) {
		fprintf(stderr, "failed to bind sv_socket! errno: %i\n", errno);
		goto main__clean_up;
	}
	if (listen(settings.sv_socket, backlog) < 0) {
		fprintf(stderr, "failed to listen on sv_socket! errno: %i\n", errno);
		goto main__clean_up;
	}

	setgid(ngid);
	if (getuid() == 0) {
		setuid(nuid);
	}

	//#ifndef NDEBUG
	// check should never pass
	if (getuid() == 0 || getgid() == 0 || geteuid() == 0 || getegid() == 0) {
		fputs("unsafe\n", stderr);
		assert(false);
		return 1;
	}
	//#endif

	if (input_addr.sun_path[0] != 0 && (input_fd = socket(AF_UNIX, SOCK_STREAM, 0)) >= 0) {
		if (bind(input_fd, (struct sockaddr *)&(input_addr), sizeof(struct sockaddr_un)) != 0) {
			fputs("failed to bind input socket\n", stderr);
			close(input_fd);
			input_fd = -1;
		} else if (listen(input_fd, 0) != 0) {
			close(input_fd);
			input_fd = -1;
		}
	}

	// signals
	signal(SIGPIPE, SIG_IGN);
	sigset_t sigset;
	sigemptyset(&(sigset));
	sigaddset(&(sigset), SIGINT);
	sigaddset(&(sigset), SIGTERM);
	settings.sigmask = sigset;
	pthread_sigmask(SIG_BLOCK, &(sigset), NULL);
	if ((sig_fd = signalfd(-1, &(sigset), 0)) < 0) {
		goto main__clean_up;
	}
	struct pollfd pollfds[2] = {
		{
			.fd = sig_fd,
			.events = POLLIN,
		},
		{
			.fd = input_fd,
			.events = POLLIN,
			.revents = 0,
		},
	};

	// serve
	bdd_instance = bdd_go(settings);
	if (bdd_instance == NULL) {
		goto main__clean_up;
	}
	if (big_alloc_sz > 0) {
		void *big_alloc = malloc(big_alloc_sz);
		if (big_alloc == NULL) {
			goto main__clean_up;
		}
		free(big_alloc);
	}

	struct signalfd_siginfo sig;
	for (;;) {
		while (poll((struct pollfd *)&(pollfds), input_fd < 0 ? 1 : 2, -1) < 0) {
			if (errno != EINTR /* e.g., SIGUSR1 could be sent to bidirectiond, and then handled by this thread */) {
				goto main__clean_up;
			}
		}
		if (pollfds[0].revents & POLLIN) {
			if (read(sig_fd, &(sig), sizeof(struct signalfd_siginfo)) != sizeof(struct signalfd_siginfo)) {
				goto main__clean_up;
			}
			switch (sig.ssi_signo) {
				case (SIGINT):
				case (SIGTERM): {
					goto main__clean_up;
				}
				default: {
					assert(false);
				}
			}
		}
		if (pollfds[1].revents & POLLIN) {
			char buf[0x100];
			input_processor(input_fd, (char *)&(buf), sizeof(buf));
		}
	}

main__clean_up:;
	if (bdd_instance != NULL) {
		bdd_stop(bdd_instance);
		bdd_wait(bdd_instance);
		bdd_destroy(bdd_instance);
	}
	if (sig_fd != -1) {
		close(sig_fd);
	}
	if (input_fd != -1) {
		unlink(input_addr.sun_path);
		close(input_fd);
	}
	if (settings.sv_socket != -1) {
		shutdown(settings.sv_socket, SHUT_RDWR);
		close(settings.sv_socket);
	}
	// aight
	if (settings.name_descriptions != NULL) {
		hashmap_destroy(settings.name_descriptions);
	}
	// https://stackoverflow.com/questions/29845527/how-to-properly-uninitialize-openssl
	// FIPS_mode_set(0);
	CRYPTO_set_locking_callback(NULL);
	CRYPTO_set_id_callback(NULL);
	// ERR_remove_state(0);
	SSL_COMP_free_compression_methods();
	ENGINE_cleanup();
	CONF_modules_free();
	CONF_modules_unload(1);
	COMP_zlib_cleanup();
	ERR_free_strings(); // TODO: is that needed?
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
	return 0;
}
#endif
