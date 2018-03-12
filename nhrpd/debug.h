#include "log.h"

#if defined(__GNUC__) && (__GNUC__ >= 3)
#define likely(_x) __builtin_expect(!!(_x), 1)
#define unlikely(_x) __builtin_expect(!!(_x), 0)
#else
#define likely(_x) !!(_x)
#define unlikely(_x) !!(_x)
#endif

#define NHRP_DEBUG_COMMON	(1 << 0)
#define NHRP_DEBUG_KERNEL	(1 << 1)
#define NHRP_DEBUG_IF		(1 << 2)
#define NHRP_DEBUG_ROUTE	(1 << 3)
#define NHRP_DEBUG_VICI		(1 << 4)
#define NHRP_DEBUG_EVENT	(1 << 5)
#define NHRP_DEBUG_ALL		(0xFFFF)

extern unsigned int debug_flags;

#if defined __STDC_VERSION__ && __STDC_VERSION__ >= 199901L

#define debugf(level, ...)                                                     \
	do {                                                                   \
		if (unlikely(debug_flags & level))                             \
			zlog_debug(__VA_ARGS__);                               \
	} while (0)

#elif defined __GNUC__

#define debugf(level, _args...)                                                \
	do {                                                                   \
		if (unlikely(debug_flags & level))                             \
			zlog_debug(_args);                                     \
	} while (0)

#else

static inline void debugf(int level, const char *format, ...)
{
}

#endif
