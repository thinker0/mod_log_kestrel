##
##  Makefile -- Build procedure for sample log_kestrel Apache module
##  Autogenerated via ``apxs -n log_kestrel -g''.
##

builddir=.
top_srcdir=/daum/program/apache
top_builddir=/daum/program/apache
include /daum/program/apache/build/special.mk

#   the used tools
APXS=apxs
APACHECTL=apachectl

#   additional defines, includes and libraries
#DEFS=-Dmy_define=my_value
#INCLUDES=-Imy/include/dir
#LIBS=-Lmy/lib/dir -lmylib

#   the default target
all: local-shared-build

#   install the shared object file into Apache 
install: install-modules-yes

#   cleanup
clean:
	-rm -f *.o *.lo *.slo *.la 

#   simple test
test: reload
	lynx -mime_header http://localhost/log_kestrel

#   install and activate shared object by reloading Apache to
#   force a reload of the shared object file
reload: install restart

#   the general Apache start/restart/stop
#   procedures
start:
	$(APACHECTL) start
restart:
	$(APACHECTL) restart
stop:
	$(APACHECTL) stop

