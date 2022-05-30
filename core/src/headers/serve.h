#ifndef bidirectiond_core__serve__h
#define bidirectiond_core__serve__h

struct bdd_instance;
static struct bdd_coac *bdd_conversations_to_epoll;
static pthread_mutex_t bdd_conversations_to_epoll_mutex;
static int
	bdd_epoll_fd,
	bdd_epoll_timeout,
	bdd_event_fd;
void *bdd_serve(struct bdd_instance *instance);

#endif
