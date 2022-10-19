@rmap@
identifier ret;
position p;
@@

int ret@p;
...
* ret = route_map_apply(...);

@script:python@
p << rmap.p;
@@

msg = "ERROR: Invalid type of return value variable for route_map_apply_ext()"
coccilib.report.print_report(p[0], msg)
