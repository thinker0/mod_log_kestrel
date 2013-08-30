MOD_FILE = mod_log_kestrel log_kestrel_memcache
mod_log_kestrel.la: ${MOD_FILE:=.slo}
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  ${MOD_FILE:=.lo}
DISTCLEAN_TARGETS = modules.mk
shared =  mod_log_kestrel.la
