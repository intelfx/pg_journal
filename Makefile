DOCS         = $(wildcard doc/*.md)
CATALOGS     = src/pg_journal_ids.catalog
SRCS         = src/pg_journal.c src/pg_journal_ids.c
OBJS         = $(patsubst %.c,%.o,$(SRCS))
MODULE_big   = pg_journal
PG_CONFIG    = pg_config
PKG_CONFIG   = pkg-config

PG_CFLAGS = $(shell $(PKG_CONFIG) libsystemd bytesize --cflags)
SHLIB_LINK = $(shell $(PKG_CONFIG) libsystemd bytesize --libs)

PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)

src/pg_journal_ids.catalog src/pg_journal_ids.c &: scripts/pg_journal_ids.py
	scripts/pg_journal_ids.py

install: install-custom
installdirs: installdirs-custom

.PHONY: installdirs-custom
installdirs-custom:
	$(MKDIR_P) '$(DESTDIR)$(libdir)/systemd/catalog'

.PHONY: install-custom
install-custom: installdirs-custom $(CATALOGS)
	$(INSTALL_DATA) $(addprefix $(srcdir)/, $(CATALOGS)) -t '$(DESTDIR)$(libdir)/systemd/catalog/'
