AUTOMAKE_OPTIONS = dist-bzip2

EXTRA_DIST = ChangeLog.svn reconf

SUBDIRS = doc src utils m4

ChangeLog.svn:
	-svn2cl --group-by-day --stdout --include-rev | perl -pe \
	's/  corcoran-guest/  David Corcoran/; \
	s/  corcoran/  David Corcoran/; \
	s/  aet-guest/  Antti Tapaninen/; \
	s/  rousseau/  Ludovic Rousseau/; \
	s/  giraud/  Jean-Luc Giraud/; \
	s+trunk/PCSC/++g;' > $@

