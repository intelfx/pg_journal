// vim: set noet sw=4 ts=4 :
/* We override CODE_FILE= etc fields, don't let systemd add these */
#define SD_JOURNAL_SUPPRESS_LOCATION 1

#include <systemd/sd-journal.h>
#include <syslog.h>

#include "postgres.h"
#include "miscadmin.h"
#include "lib/stringinfo.h"
#include "libpq/libpq-be.h"
#include "tcop/tcopprot.h"
#include "utils/elog.h"
#include "utils/memutils.h"

/**** Version detection */

#ifdef __GNUC__
# if PG_VERSION_NUM < 90200
/*
 * There's no way to detect whether the patch was already applied, so this is
 * just a warning.
 */
#  warning "Building on PostgreSQL version earlier than 9.2. If the build fails, you"
#  warning "need to patch the PostgreSQL server first. You can get the patch from:"
#  warning "https://raw.github.com/intgr/pg_journal/master/patches/logging-hooks.patch"
# endif
#endif

/**** Declarations */

PG_MODULE_MAGIC;

void PGDLLEXPORT _PG_init(void);
void PGDLLEXPORT _PG_fini(void);

static void do_emit_log(ErrorData *edata);
static void journal_emit_log(ErrorData *edata);

/**** Globals */

static emit_log_hook_type prev_emit_log_hook = NULL;
/* If a failure occurs, report it to the server log the first time */
static bool reported_failure = false;
/* GUC pg_journal.passthrough_server_log = off */
static bool passthrough_server_log = false;
/* Cache syslog_ident */
static char *syslog_ident = NULL;

/**** Implementation */

/* Convenience wrapper for DefineCustomBoolVariable */
static void
DefineBoolVariable(const char *name, const char *short_desc, bool *value_addr)
{
	DefineCustomBoolVariable(
		name,
		short_desc,
		NULL,
		value_addr,
#if PG_VERSION_NUM >= 80400
		false,                /* bootValue since 8.4 */
		PGC_SUSET,
		0,
#else
		PGC_USERSET,		/* 8.3 only allows USERSET custom params */
#endif
#if PG_VERSION_NUM >= 90100
		NULL,                /* check_hook parameter since 9.1 */
#endif
		NULL,
		NULL
	);
}

void
_PG_init(void)
{
	ereport(
		LOG,
		errmsg("pg_journal: setting up"),
		errhint("future log output will be sent to the journal")
	);

	DefineBoolVariable(
		"pg_journal.passthrough_server_log",
		"Duplicate messages to the server log even if journal logging succeeds",
		&passthrough_server_log
	);

	/*
	 * We don't want to perform this GUC lookup for each log message. Sadly
	 * there is no nice way to get notified when this changes.
	 */
	syslog_ident = MemoryContextStrdup(
		TopMemoryContext, GetConfigOption(
			"syslog_ident", false, false
		));

	prev_emit_log_hook = emit_log_hook;
	emit_log_hook = do_emit_log;

	ereport(
		LOG,
		errmsg("pg_journal: ready")
	);
}

void
_PG_fini(void)
{
	/*
	 * If not, someone else didn't clean up properly. We can't do anything here.
	 */
	if (emit_log_hook != do_emit_log)
		ereport(
			FATAL,
			errmsg("pg_journal: emit_log_hook has been changed, cannot shut down")
		);

	ereport(
		LOG,
		errmsg("pg_journal: shutting down"),
		errhint("future log output will be sent to the configured server log")
	);

	emit_log_hook = prev_emit_log_hook;

	ereport(
		LOG,
		errmsg("pg_journal: shut down, resuming normal server log output")
	);
}

static void
do_emit_log(ErrorData *edata)
{
	static bool in_hook = false;

	/* Call any previous hooks */
	if (prev_emit_log_hook)
		prev_emit_log_hook(edata);

	/* Protect from recursive calls */
	if (!in_hook) {
		in_hook = true;
		journal_emit_log(edata);
		in_hook = false;
	}
}

static int
elevel_to_syslog(int elevel)
{
	/* See utils/error/elog.c function send_message_to_server_log */
	switch (elevel) {
		case DEBUG5:
		case DEBUG4:
		case DEBUG3:
		case DEBUG2:
		case DEBUG1:
			return LOG_DEBUG;
		case LOG:
		case LOG_SERVER_ONLY:
		case INFO:
			return LOG_INFO;
		case NOTICE:
		case WARNING:
		case WARNING_CLIENT_ONLY:
			return LOG_NOTICE;
		case ERROR:
			return LOG_WARNING;
		case FATAL:
			return LOG_ERR;
		case PANIC:
		default:
			return LOG_CRIT;
	}
}

static int
strprefixcmp(const char *str1, const char *prefix)
{
	return strncmp(str1, prefix, strlen(prefix));
}

/*
 * This is a slight abuse of the StringInfo system. We're simply concatenating
 * together lots of fields and storing their lengths. Once the whole string
 * is ready, we get pointers based on the lengths.
 *
 * This is better than using a separate StringInfo for each field, since
 * each StringInfo consumes 1024 bytes by default. A typical user message, 12
 * fields, would then consume 12 kilobytes minimum!
 */

#define MAX_FIELDS  23 /* NB! Keep this in sync when adding fields! */

struct fieldbuf
{
	struct iovec iov[MAX_FIELDS];
	size_t n;
};

/* @formatter:off */

#define APPEND_PROLOGUE(buf, fields)											\
	size_t old_len = (buf)->len;												\
	if ((fields)->n >= (sizeof((fields)->iov) / sizeof((fields)->iov[0]))) {	\
		ereport(FATAL,															\
				(errmsg("pg_journal: too many log fields (%zu >= %zu)",			\
						(fields)->n,											\
						sizeof((fields)->iov) / sizeof((fields)->iov[0]))));	\
	}																			\

#define APPEND_EPILOGUE(buf, fields)											\
	(fields)->iov[(fields)->n++].iov_len = (buf)->len - old_len;				\

#define appendf(buf, fields, fmt, ...)											\
	do {																		\
		APPEND_PROLOGUE(buf, fields)											\
		appendStringInfo(buf, fmt, ##__VA_ARGS__);								\
		APPEND_EPILOGUE(buf, fields)											\
	} while (0)																	\

#define append2(buf, fields, s1, s2)											\
	do {																		\
		APPEND_PROLOGUE(buf, fields)											\
		appendStringInfoString(buf, s1);										\
		appendStringInfoString(buf, s2);										\
		APPEND_EPILOGUE(buf, fields)											\
	} while (0)																	\

#define append4(buf, fields, s1, s2, s3, s4)									\
	do {																		\
		APPEND_PROLOGUE(buf, fields)											\
		appendStringInfoString(buf, s1);										\
		appendStringInfoString(buf, s2);										\
		appendStringInfoString(buf, s3);										\
		appendStringInfoString(buf, s4);										\
		APPEND_EPILOGUE(buf, fields)											\
	} while (0)																	\

/* @formatter:on */

static void
journal_emit_log(ErrorData *edata)
{
	struct fieldbuf fields = {};
	StringInfoData buf;
	int ret;
	char *ptr;

	if (!edata->output_to_server)
		return;

	initStringInfo(&buf);

	/* Assign a MESSAGE_ID to log_statement logging */
	if (edata->hide_stmt && debug_query_string != NULL &&
	    !strprefixcmp(edata->message, "statement: ")) {
		append2(&buf, &fields,
			"MESSAGE_ID=",
			"a63699368b304b4cb51bce5644736306"
		);
	}

	if (edata->message)
		append4(&buf, &fields,
			"MESSAGE=",
			_(error_severity(edata->elevel)),
			":  ",
			edata->message
		);

	appendf(&buf, &fields, "PRIORITY=%d", elevel_to_syslog(edata->elevel));
	appendf(&buf, &fields, "PGLEVEL=%d", edata->elevel);

	if (edata->sqlerrcode)
		append2(&buf, &fields,
			"SQLSTATE=", unpack_sql_state(edata->sqlerrcode)
		);

	if (edata->detail_log)
		append2(&buf, &fields, "DETAIL=", edata->detail_log);
	else if (edata->detail)
		append2(&buf, &fields, "DETAIL=", edata->detail);

	if (edata->hint)
		append2(&buf, &fields, "HINT=", edata->hint);

	if (edata->internalquery)
		append2(&buf, &fields, "QUERY=", edata->internalquery);

	if (!edata->hide_ctx && edata->context)
		append2(&buf, &fields, "CONTEXT=", edata->context);

	if (!edata->hide_stmt && debug_query_string)
		append2(&buf, &fields, "STATEMENT=", debug_query_string);

#if PG_VERSION_NUM >= 90300
	if (edata->schema_name)
		append2(&buf, &fields, "SCHEMA=", edata->schema_name);
	if (edata->table_name)
		append2(&buf, &fields, "TABLE=", edata->table_name);
	if (edata->column_name)
		append2(&buf, &fields, "COLUMN=", edata->column_name);
	if (edata->datatype_name)
		append2(&buf, &fields, "DATATYPE=", edata->datatype_name);
	if (edata->constraint_name)
		append2(&buf, &fields, "CONSTRAINT=", edata->constraint_name);
#endif /* PG_VERSION_NUM >= 90300 */

	/*
	 * These fields are normally added by systemd itself, but we override them
	 * to contain the actual PostgreSQL logging call. Not sure how useful they
	 * are in practice.
	 */
#ifdef SD_JOURNAL_SUPPRESS_LOCATION
	if (edata->filename)
		append2(&buf, &fields, "CODE_FILE=", edata->filename);
	if (edata->lineno > 0)
		appendf(&buf, &fields, "CODE_LINE=%d", edata->lineno);
	if (edata->funcname)
		append2(&buf, &fields, "CODE_FUNCTION=", edata->funcname);
#endif /* SD_JOURNAL_SUPPRESS_LOCATION */

	/*
	 * Non-ErrorData fields. These field names are named after libpq
	 * environment vars:
	 * http://www.postgresql.org/docs/current/static/libpq-envars.html
	 */
	if (MyProcPort) {
		if (MyProcPort->user_name)
			append2(&buf, &fields, "PGUSER=", MyProcPort->user_name);

		if (MyProcPort->database_name)
			append2(&buf, &fields, "PGDATABASE=", MyProcPort->database_name);

		if (MyProcPort->remote_host && MyProcPort->remote_port &&
		    MyProcPort->remote_port[0] != '\0')
			append4(&buf, &fields,
				"PGHOST=",
				MyProcPort->remote_host,
				":",
				MyProcPort->remote_port
			);
		else if (MyProcPort->remote_host)
			append2(&buf, &fields,
				"PGHOST=",
				MyProcPort->remote_host
			);
	}

	if (application_name && application_name[0] != '\0')
		append2(&buf, &fields, "PGAPPNAME=", application_name);

	append2(&buf, &fields, "SYSLOG_IDENTIFIER=", syslog_ident);

	/*
	 * Done writing fields. Need to extract pointers to individual items, by
	 * following field lengths. We couldn't do that before, since the string's
	 * base address can move due to reallocations.
	 */
	ptr = buf.data;
	for (size_t i = 0; i < fields.n; i++) {
		fields.iov[i].iov_base = ptr;
		ptr += fields.iov[i].iov_len;
	}

	ret = sd_journal_sendv(fields.iov, (int) fields.n);
	pfree(buf.data);

	if (ret >= 0) {
		/* Successfully logged */
		if (!passthrough_server_log)
			edata->output_to_server = false;
	} else {
		if (!reported_failure) {
			ereport(
				WARNING,
				errmsg("pg_journal: could not log message with %zu fields: %s",
				       fields.n, strerror(-ret))
			);
			/* Prevent spamming the log on subsequent failures */
			reported_failure = true;
		}
	}
}
