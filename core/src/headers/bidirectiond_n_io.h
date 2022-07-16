#ifndef bdd__bidirectiond_n_io__h
#define bdd__bidirectiond_n_io__h
typedef unsigned short int bdd_io_id;
#ifndef BIDIRECTIOND_N_IO
#define BIDIRECTIOND_N_IO 2
#endif
#include <assert.h>
static_assert(BIDIRECTIOND_N_IO < USHRT_MAX, "BIDIRECTIOND_N_IO is greater than or equal to USHRT_MAX");
#endif