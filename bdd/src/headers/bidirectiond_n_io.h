#ifndef BIDIRECTIOND_N_IO

#define BIDIRECTIOND_N_IO 2ULL
typedef unsigned short int bdd_io_id;

struct BDD_STATIC_ASSERT_BIDIRECTIOND_N_IO { char ASSERT : (BIDIRECTIOND_N_IO < (unsigned long long int)(bdd_io_id)(-1) ? 1 : 0); };

#endif
