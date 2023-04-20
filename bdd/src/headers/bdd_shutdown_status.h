#ifndef bidirectiond__bdd_shutdown_status__h
#define bidirectiond__bdd_shutdown_status__h

enum bdd_shutdown_status {
	bdd_shutdown_conversation_discard,
	bdd_shutdown_inprogress,
	bdd_shutdown_complete, // wrhup but no rdhup
	bdd_shutdown_discard, // wrhup and rdhup
};

#endif
