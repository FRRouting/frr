# Scan a file of route-type definitions (see eg route_types.txt) and
# generate a corresponding header file with:
#
# - enum of Zserv route-types
# - redistribute strings for the various Quagga daemons
#
# See route_types.txt for the format.
#
#

BEGIN {
	FS="[,]";
	
	# globals
	exitret = 0;
	tcount = 0;
	
	# formats for output
	## the define format
	redist_def_fmt = "#define QUAGGA_REDIST_STR_%s \\\n";
	## DEFUN/vty route-type argument
	redist_str_fmt = "\"(%s)\"\n";
	redist_help_def_fmt = "#define QUAGGA_REDIST_HELP_STR_%s";
	redist_help_str_fmt = " \\\n  \"%s\\n\"";
	
	# header
	header = "/* Auto-generated from route_types.txt by " ARGV[0] ". */\n";
	header = header "/* Do not edit! */\n";
	header = header "\n#ifndef _QUAGGA_ROUTE_TYPES_H\n";
	header = header "#define _QUAGGA_ROUTE_TYPES_H\n";
	footer = "#endif /* _QUAGGA_ROUTE_TYPES_H */\n";
	printf ("%s\n", header);
}

# Chomp comment lines
($0 ~ /^#/) { 
	next;
}

# get rid of the commas, leading/trailling whitespace and
# quotes
{
	for (i = 1; i <= NF; i++) {
		#print "before:" $i;
		$i = gensub(/^[[:blank:]]*(.*)[,]*.*/, "\\1", "g",$i);
		$i = gensub(/^["](.*)["]$/, "\\1", "g", $i);
		#print "after :" $i;
	}
}

# 7 field format:
#  type                 cname      daemon  C    4  6  short help
(NF >= 7) {
	#print "7", $1, $0;
	
	if ($1 in types) {
		print "error: attempt to redefine", $1;
		exitret = 1;
		exit exitret;
	}
	
	typesbynum[tcount] = $1;
	types[$1,"num"] = tcount++; 
	types[$1,"cname"] = $2;
	types[$1,"daemon"] = $3;
	types[$1,"C"] = $4;
	types[$1,"4"] = strtonum($5);
	types[$1,"6"] = strtonum($6);
	types[$1,"shelp"] = $7;
	
	#print "num   :", types[$1,"num"]
	#print "cname :", types[$1,"cname"]
	#print "daemon:", types[$1,"daemon"];
	#print "char  :", types[$1,"C"];
};

# 2 field: type "long description"
(NF == 2) {
	#print "2", $1, $2;
	
	if (!(($1 SUBSEP "num") in types)) {
		print "error: type", $1, "must be defined before help str";
		exitret = 2;
		exit exitret;
	}
	
	types[$1,"lhelp"] = $2;
}

END {
	if (exitret)
		exit exitret;
	
	# The enums
	# not yet...
	#printf("enum\n{\n");
	#for (i = 0; i < tcount; i++) {
	#	type = typesbynum[i];
	#	if (type != "" && types[type,"num"] == i)
	#		printf ("  %s,\n", type);
	#}
	#printf ("  ZEBRA_ROUTE_MAX,\n};\n\n");
	
	# the redistribute defines
	for (i = 0; i < tcount; i++) {
		type = typesbynum[i];
		
		# must be a type, and must cross-check against recorded type
		if (type == "" || types[type,"num"] != i)
			continue;
		
		# ignore route types that can't be redistributed
		if (!(types[type,"4"] || types[type,"6"]))
			continue;
		
		# must have a daemon name
		if (!((type SUBSEP "daemon") in types))
			continue;
		if (!(daemon = types[type,"daemon"]))
			continue;
		
		# might have done this daemon already?
		if (daemon in seen_daemons)
			continue;
		
		cname = types[type,"cname"];
		all = all "|" cname;
		rstr = "";
		hstr = "";
		
		# add it to the others
		for (j = 0; j < tcount; j++) {
			# ignore self
			if (i == j)
				continue;
			
			type2 = typesbynum[j];
			
			# type2 must be valid, and self-check.
			if (type2 == "" || types[type2,"num"] != j)
				continue;
			
			# ignore different route types for the same daemon
			# (eg system/kernel/connected)
			if (types[type2,"daemon"] == daemon)
				continue;
			
			if ((types[type2,"4"] && types[type,"4"]) \
			    || (types[type2,"6"] && types[type,"6"])) {
			    	
			    	if (rstr == "")
			    		rstr = types[type2,"cname"];
				else
					rstr = rstr "|" types[type2,"cname"];
				
				if ((type2 SUBSEP "lhelp") in types)
				  hstr2 = types[type2,"lhelp"];
				else if ((type2 SUBSEP "shelp") in types)
				  hstr2 = types[type2,"shelp"];
				else
				  hstr2 = types[type2,"cname"];
				
				hstr = hstr sprintf(redist_help_str_fmt, hstr2);
			}
		}
		
		# dont double-process daemons.
		seen_daemons[daemon] = 1;
		
		printf("/* %s */\n", daemon);
		printf(redist_def_fmt, toupper(daemon));
		printf(redist_str_fmt, rstr);
		printf(redist_help_def_fmt, toupper(daemon));
		printf("%s", hstr);
		printf("\n\n");
	}
	
	#printf("#define QUAGGA_REDIST_STR_ALL %s\n",all);
			
#	for (i = 0; i < lcount; i++) {
#		if (mlists[i] != "")
#			printf (mlistformat "\n", mlists[i]);
#	}
	printf (footer);
}
