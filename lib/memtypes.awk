# $Id: memtypes.awk,v 1.1 2005/04/15 11:47:15 paul Exp $
#
# Scan a file of memory definitions (see eg memtypes.c) and generate
# a corresponding header file with an enum of the MTYPE's and declarations
# for the struct memory_list arrays
#

BEGIN {
	mlistregex = "memory_list_(.*)\\[\\]";
	mtyperegex = "^.*(MTYPE_[A-Z_0-9]+).*$";
	header = "/* Auto-generated from memtypes.c by " ARGV[0] ". */\n";
	header = header "/* Do not edit! */\n";
	header = header "\n#ifndef _QUAGGA_MEMTYPES_H\n";
	header = header "#define _QUAGGA_MEMTYPES_H\n";
	footer = "\n#endif /* _QUAGGA_MEMTYPES_H */\n\n";
	mlistformat = "extern struct memory_list memory_list_%s[];";
	printf ("%s\n", header);
}

($0 ~ /^struct memory_list /) && (NF >= 3) {
	mlists[lcount++] = gensub(mlistregex,"\\1",g,$3);
}

($1 != "/*") && ($1 != "*") && ($2 ~ /MTYPE_/) { 
	mtype[tcount++] = gensub(mtyperegex,"\\1",1, $0);
} 

END {
	printf("enum\n{\n  MTYPE_TMP = 1,\n"); 
	for (i = 0; i < tcount; i++) {
		if (mtype[i] != "" && mtype[i] != "MTYPE_TMP")
			printf ("  %s,\n", mtype[i]);
	}
	printf ("  MTYPE_MAX,\n};\n\n");
	for (i = 0; i < lcount; i++) {
		if (mlists[i] != "")
			printf (mlistformat "\n", mlists[i]);
	}
	printf (footer);
}
