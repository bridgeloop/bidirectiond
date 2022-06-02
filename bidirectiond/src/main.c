#include "core_settings.h"
#include "cp_pwd.h"
#include "input_processor.h"
#include "strtoint.h"

#include <poll.h>
#include <assert.h>
#include <arpa/inet.h>
#include <bdd-core/settings.h>
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
	.name_descs = NULL,
	.n_conversations = 0x100,
	.n_epoll_oevents = 0x200,
	.n_worker_threads = 16,
	.epoll_timeout = -1,
	.sockfds = NULL,
};

#define PASTE(x, y) x##y
#define sto(sign, w, t) \
	bool PASTE(sto, w)(t * dest, char *str) { \
		sign long long int v; \
		if (strcmp(#sign, "signed") == 0) { \
			if (!strtolls(str, strlen(str), &(v))) { \
				return false; \
			} \
		} else { \
			if (!strtollu(str, strlen(str), &(v))) { \
				return false; \
			} \
		} \
		if (v == (t)v) { \
			*dest = (t)v; \
			return true; \
		} \
		return false; \
	}
sto(signed, i, int);
sto(unsigned, ui, unsigned int);
sto(unsigned, usi, unsigned short int);
sto(signed, uid, uid_t);
sto(signed, gid, gid_t);
sto(unsigned, sz, size_t);
sto(unsigned, rlim, rlim_t);

// main
#ifndef HASHMAP_MAIN
int main(int argc, char *argv[], char *env[]) {
	// set up tls
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
	ERR_load_BIO_strings();
	ERR_load_crypto_strings();

	bool bdd_instance;
	int input_fd = -1;
	int *sockfds = NULL;
	size_t fuck_idx = 0; // to-do: rename that variable
	struct sockaddr_un input_addr = {
		0,
		.sun_family = AF_UNIX,
	};
	int sig_fd = -1;

	// name_descs
	if ((settings.name_descs = bdd_name_descs_create()) == NULL) {
		fputs("failed to allocate settings.name_descs\n", stderr);
		goto clean_up;
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

	size_t big_alloc_sz = 0;

	#define EXPECT_ARGS(n) \
		for (size_t idx = 1; idx <= n; ++idx) { \
			if (arg[idx] == NULL || (arg[idx][0] == '-' && (arg[idx][1] < '1' || arg[idx][1] > '9'))) { \
				goto arg_err; \
			} \
		}
	#define EXPECT(n) \
		if (!n) { \
			goto arg_err; \
		}
	arg_iter:;
	while ((*arg) != NULL) {
		if (strcmp((*arg), "--n-worker-threads") == 0 || strcmp((*arg), "-t") == 0) {
			EXPECT_ARGS(1);
			EXPECT(stousi(&(settings.n_worker_threads), arg[1]));
			arg += 2;
		} else if (strcmp((*arg), "-l") == 0) {
			EXPECT_ARGS(2);
			struct rlimit rlimit;
			EXPECT(storlim(&(rlimit.rlim_cur), arg[1]));
			EXPECT(storlim(&(rlimit.rlim_max), arg[2]));
			if (setrlimit(RLIMIT_NOFILE, &(rlimit)) != 0) {
				fputs("setrlimit failed\n", stderr);
			}
			arg += 3;
		} else if (strcmp((*arg), "--backlog") == 0) {
			EXPECT_ARGS(1);
			EXPECT(stoi(&(backlog), arg[1]));
			arg += 2;
		} else if (strcmp((*arg), "--server-tcp-port") == 0 || strcmp((*arg), "-p") == 0) {
			EXPECT_ARGS(1);
			EXPECT(stousi(&(port), arg[1]));
			arg += 2;
		}  else if (strcmp((*arg), "--epoll-timeout") == 0) {
			EXPECT_ARGS(1);
			EXPECT(stoi(&(settings.epoll_timeout), arg[1]));
			arg += 2;
		} else if (strcmp((*arg), "--max-conversations") == 0) {
			EXPECT_ARGS(1);
			EXPECT(stoi(&(settings.n_conversations), arg[1]));
			arg += 2;
		} else if (strcmp((*arg), "--disable-ipv6") == 0) {
			disable_ipv6 = true;
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
			X509 *x509 = NULL;
			EVP_PKEY *pkey = NULL;

			// read x509 //

			FILE *file = fopen(arg[1], "r");
			if (file == NULL) {
				fprintf(stderr, "couldn't access certificate file (%s)\n", arg[1]);
				goto arg_creds_err;
			}

			x509 = PEM_read_X509(file, NULL, NULL, NULL);
			fclose(file);

			if (x509 == NULL) {
				fprintf(stderr, "invalid certificate file (%s)\n", arg[1]);
				goto arg_creds_err;
			}

			// read private key //

			struct cp_pwd_ctx cp_ctx = {
				.success = false,
				.password = getenv(arg[3]),
			};

			file = fopen(arg[2], "r");
			if (file == NULL) {
				fprintf(stderr, "couldn't access private key file (%s)\n", arg[1]);
				goto arg_creds_err;
			}

			pkey = PEM_read_PrivateKey(file, NULL, &(cp_pwd), &(cp_ctx));
			fclose(file);

			if (pkey == NULL) {
				fprintf(stderr, "invalid private key file (%s)\n", arg[2]);
				goto arg_creds_err;
			}
			if (!cp_ctx.success) {
				fputs("the private key file must be encrypted\n", stderr);
				goto arg_creds_err;
			}

			if (!bdd_name_descs_use_cert_pkey(settings.name_descs, &(x509), &(pkey))) {
				fputs("seemingly invalid certificate file\n", stderr);
				goto arg_creds_err;
			}

			arg_creds_err:;
			if (x509 != NULL) {
				X509_free(x509);
			}
			if (pkey != NULL) {
				EVP_PKEY_free(pkey);
			}

			arg += 4;
		} else if (getuid() == 0 && strcmp((*arg), "--uid") == 0) {
			EXPECT_ARGS(1);
			EXPECT(stouid(&(nuid), arg[1]));
			arg += 2;
		} else if (getgid() == 0 && strcmp((*arg), "--gid") == 0) {
			EXPECT_ARGS(1);
			EXPECT(stogid(&(ngid), arg[1]));
			arg += 2;
		} else if (strcmp((*arg), "--n-epoll-oevents") == 0) {
			EXPECT_ARGS(1);
			EXPECT(stoi(&(settings.n_epoll_oevents), arg[1]));
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
			EXPECT(stosz(&(big_alloc_sz), arg[1]));
			arg += 2;
		} else {
			for (size_t idx = 0; idx < n_services; ++idx) {
				if (services[idx].supported_arguments != NULL)
					for (size_t pidx = 0; services[idx].supported_arguments[pidx]; ++pidx) {
						if (strcmp((*arg), services[idx].supported_arguments[pidx]) == 0) {
							size_t n = 1;
							while (
								arg[n] != NULL &&
								(arg[n][0] != '-'  ||
								(arg[n][1] >= '0' && arg[n][1] <= '9'))
							) {
								n += 1;
							}
							if (!services[idx].instantiate(
								settings.name_descs,
								&(services[idx]),
								n,
								(const char **)arg
							)) {
								goto arg_err;
							}
							arg = &(arg[n]);
							goto arg_iter;
						}
					}
			}
			arg_err:;
			fputs("argument parsing failed\n"
			     "-t: set the amount of worker threads\n"
			     "--client-timeout: set the timeout (in ms) for "
			     "client socket i/o\n"
			     "--epoll-timeout: set the timeout (in ms) for "
			     "bdd_conversation structs\n"
			     "-l: set the rlimits for open files (soft limit, "
			     "hard limit)\n"
			     "--backlog: set the tcp backlog for sv_socket\n"
			     "-p: set the tcp port to bind sv_socket to\n"
			     "--max-conversations: the max amount of "
			     "bdd_conversation structs\n"
			     "--disable-ipv6: sv_socket should not use ipv6\n"
			     "--nohup: SIG_IGN SIGHUP\n"
			     "-c: load pem-encoded tls credentials (e.g. `-c "
			     "cert.pem encrypted-key.pem "
			     "name-of-password-environment-variable`)\n"
			     "--input: set the path for a tcp unix socket, so "
			     "that some bidirectiond settings can be modified "
			     "without restarting\n"
			     "--n-epoll-oevents: epoll_wait maxevents\n"
			     "--big-alloc: reserve some memory\n", stdout);
			for (size_t idx = 0; idx < n_services; ++idx) {
				if (services[idx].arguments_help != NULL) {
					fputs(services[idx].arguments_help, stdout);
				}
			}
			goto clean_up;
		}
	}

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
	int af;
	if (disable_ipv6) {
		sv_addr_sz = sizeof(struct sockaddr_in);
		af = sv_addr.inet4.sin_family = AF_INET;
		sv_addr.inet4.sin_addr.s_addr = INADDR_ANY;
		sv_addr.inet4.sin_port = htons(port);
	} else {
		sv_addr_sz = sizeof(struct sockaddr_in6);
		af = sv_addr.inet6.sin6_family = AF_INET6;
		sv_addr.inet6.sin6_addr = in6addr_any;
		sv_addr.inet6.sin6_port = htons(port);
	}
	// try to bind to port
	sockfds = malloc(sizeof(int) * settings.n_worker_threads);
	if (sockfds == NULL) {
		goto clean_up;
	}
	for (; fuck_idx < settings.n_worker_threads; ++fuck_idx) {
		int fd = socket(af, SOCK_STREAM | SOCK_NONBLOCK, 0);
		if (fd < 0) {
			fprintf(stderr, "failed to create sv_socket! errno: %i\n", errno);
			goto sock_err;
		}
		int opt = 1;
		setsockopt(fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &(opt), sizeof(opt));
		if (bind(fd, (struct sockaddr *)&(sv_addr), sv_addr_sz) < 0) {
			fprintf(stderr, "failed to bind sv_socket! errno: %i\n", errno);
			goto sock_err;
		}
		if (listen(fd, backlog) < 0) {
			fprintf(stderr, "failed to listen on sv_socket! errno: %i\n", errno);
			goto sock_err;
		}
		sockfds[fuck_idx] = fd;
		continue;

		sock_err:;
		close(fd);
		goto clean_up;
	}
	settings.sockfds = sockfds;

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

	if (input_addr.sun_path[0] != 0) {
		input_fd = socket(AF_UNIX, SOCK_STREAM, 0);
		if (input_fd >= 0) {
			if (bind(input_fd, (struct sockaddr *)&(input_addr), sizeof(struct sockaddr_un)) != 0) {
				fputs("failed to bind input socket\n", stderr);
				close(input_fd);
				input_fd = -1;
			} else if (listen(input_fd, 0) != 0) {
				fputs("failed to listen on input socket\n", stderr);
				close(input_fd);
				input_fd = -1;
			}
		} else {
			fputs("failed to create input socket\n", stderr);
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
		goto clean_up;
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
	if (!bdd_instance) {
		goto clean_up;
	}
	if (big_alloc_sz > 0) {
		void *big_alloc = malloc(big_alloc_sz);
		if (big_alloc == NULL) {
			goto clean_up;
		}
		free(big_alloc);
	}

	struct signalfd_siginfo sig;
	for (;;) {
		while (poll((struct pollfd *)&(pollfds), input_fd < 0 ? 1 : 2, -1) < 0) {
			if (errno
			    != EINTR /* e.g., SIGUSR1 could be sent to bidirectiond, and then handled by this thread */)
			{
				goto clean_up;
			}
		}
		if (pollfds[0].revents & POLLIN) {
			if (read(sig_fd, &(sig), sizeof(struct signalfd_siginfo)) != sizeof(struct signalfd_siginfo)) {
				goto clean_up;
			}
			switch (sig.ssi_signo) {
				case (SIGINT):
				case (SIGTERM): {
					goto clean_up;
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

	clean_up:;
	if (bdd_instance) {
		bdd_stop();
		bdd_wait();
		bdd_destroy();
	}
	if (sig_fd != -1) {
		close(sig_fd);
	}
	if (input_fd != -1) {
		unlink(input_addr.sun_path);
		close(input_fd);
	}
	if (sockfds != NULL) {
		for (size_t idx = 0; idx < fuck_idx; ++idx) {
			shutdown(sockfds[idx], SHUT_RDWR);
			close(sockfds[idx]);
		}
		free(sockfds);
	}
	// aight
	if (settings.name_descs != NULL) {
		bdd_name_descs_destroy(&(settings.name_descs));
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
	ERR_free_strings();
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
	return 0;
}
#endif
