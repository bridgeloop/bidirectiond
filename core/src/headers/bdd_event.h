#ifndef bidirectiond_core__bdd_event__h
#define bidirectiond_core__bdd_event__h

#define bdd_ev_in 1
#define bdd_ev_out 2
#define bdd_ev_removed 4

struct bdd_ev {
	uint8_t events;
	uint8_t io_id;
};

#endif
