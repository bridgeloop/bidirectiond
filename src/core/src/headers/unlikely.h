#ifndef unlikely
#define unlikely(x) __builtin_expect((x), 0)
#endif
