#include <stddef.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <unistd.h>

typedef unsigned long mytype;
typedef size_t mysize;

typedef unsigned int not_in_addr_t;
typedef in_addr_t yes_in_addr_t;
typedef struct in_addr in_addr_s;

struct other {
	int x;
};

int testfn(const char *fmt, ...) __attribute__((frr_format("frr_printf", 1, 2)));

#ifndef _FRR_ATTRIBUTE_PRINTFRR
#error please load the frr-format plugin
#endif

#pragma FRR printfrr_ext "%pI4" (struct in_addr *)
#pragma FRR printfrr_ext "%pI4" (in_addr_t *)

int test(unsigned long long ay)
{
	size_t v_size_t = 0;
	long v_long = 0;
	int v_int = 0;
	uint64_t v_uint64_t = 0;
	mytype v_mytype = 0;
	mysize v_mysize = 0;
	pid_t v_pid_t = 0;

	testfn("%zu", v_size_t);		// NOWARN
	testfn("%zu", v_long);			// WARN
	testfn("%zu", v_int);			// WARN
	testfn("%zu", sizeof(v_int));		// NOWARN
	testfn("%zu", v_mytype);		// WARN
	testfn("%zu", v_mysize);		// NOWARN
	testfn("%zu", v_uint64_t);		// WARN
	testfn("%zu", v_pid_t);			// WARN

	testfn("%lu", v_long);			// NOWARN PEDANTIC
	testfn("%lu", v_int);			// WARN
	testfn("%lu", v_size_t);		// WARN
	testfn("%lu", sizeof(v_int));		// NOWARN (integer constant)
	testfn("%lu", v_uint64_t);		// WARN
	testfn("%lu", v_pid_t);			// WARN

	testfn("%ld", v_long);			// NOWARN
	testfn("%ld", v_int);			// WARN
	testfn("%ld", v_size_t);		// WARN
	testfn("%ld", sizeof(v_int));		// NOWARN (integer constant)
	testfn("%ld", v_uint64_t);		// WARN
	testfn("%ld", v_pid_t);			// WARN

	testfn("%d",  v_int);			// NOWARN
	testfn("%d",  v_long);			// WARN
	testfn("%d",  v_size_t);		// WARN
	testfn("%d",  sizeof(v_int));		// WARN
	testfn("%d",  v_uint64_t);		// WARN
	testfn("%d",  v_pid_t);			// WARN

	testfn("%Lu", v_size_t);		// WARN
	testfn("%Lu", v_long);			// WARN
	testfn("%Lu", v_int);			// WARN
	testfn("%Lu", sizeof(v_int));		// NOWARN (integer constant)
	testfn("%Lu", v_mytype);		// WARN
	testfn("%Lu", v_mysize);		// WARN
	testfn("%Lu", v_pid_t);			// WARN
	testfn("%Lu", v_uint64_t);		// NOWARN

	testfn("%Ld", v_size_t);		// WARN
	testfn("%Ld", v_long);			// WARN
	testfn("%Ld", v_int);			// WARN
	testfn("%Ld", sizeof(v_int));		// NOWARN (integer constant)
	testfn("%Ld", v_mytype);		// WARN
	testfn("%Ld", v_mysize);		// WARN
	testfn("%Ld", v_pid_t);			// WARN
	testfn("%Ld", v_uint64_t);		// NOWARN

	/* retain-typeinfo patch */
	testfn("%zu", (size_t)v_pid_t);         // NOWARN (need retain-typeinfo patch)
	testfn("%lu", (size_t)v_pid_t);         // WARN   (need retain-typeinfo patch)
	testfn("%Lu", (uint64_t)v_pid_t);       // NOWARN (need retain-typeinfo patch)
	testfn("%lu", (uint64_t)v_pid_t);       // WARN   (need retain-typeinfo patch)

	testfn("%pI4", &v_long);		// WARN

	in_addr_t v_in_addr_t;
	yes_in_addr_t v_yes_in_addr_t;
	not_in_addr_t v_not_in_addr_t;
	void *v_voidp = &v_in_addr_t;

	testfn("%pI4", &v_in_addr_t);		// NOWARN
	testfn("%pI4", &v_yes_in_addr_t);	// NOWARN
	testfn("%pI4", &v_not_in_addr_t);	// WARN
	testfn("%pI4", v_voidp);		// WARN

	struct in_addr v_in_addr;
	in_addr_s v_in_addr_s;
	struct other v_other;
	const struct in_addr *v_in_addr_const = &v_in_addr;

	testfn("%pI4", &v_in_addr);		// NOWARN
	testfn("%pI4", &v_in_addr_s);		// NOWARN
	testfn("%pI4", &v_other);		// WARN
	testfn("%pI4", v_in_addr_const);	// NOWARN
	return 0;
}
