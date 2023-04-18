// spatch -sp_file tools/coccinelle/cast_to_larger_sizes.cocci --recursive-includes ./

@r@
typedef uint8_t;
typedef uint16_t;
typedef uint32_t;
typedef uint64_t;
uint8_t *i8;
position p;
@@

 \(
  (uint64_t *) i8@p\|(uint32_t *) i8@p\|(uint16_t *) i8@p
 \)

@script:python@
p << r.p;
@@

coccilib.report.print_report(p[0],"Bad typecast to larger size")
