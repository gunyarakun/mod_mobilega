lib_LTLIBRARIES = mod_mobilega.la
mod_mobilega_la_CFLAGS = @CFLAGS@
mod_mobilega_la_SOURCES = mod_mobilega.c
mod_mobilega_la_LDFLAGS = -module -export-dynamic -avoid-version -no-undefined

install:
	cp .libs/mod_mobilega.so @LIGHTTPD_PLUGIN@

debug:
	sudo gdb --args /www/lighttpd/sbin/lighttpd -D -f /www/lighttpd/etc/main.conf
