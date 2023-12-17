//
// Created by intelfx on 17.12.23.
//

#ifndef PG_JOURNAL_PG_JOURNAL_IDS_H
#define PG_JOURNAL_PG_JOURNAL_IDS_H

#include <stddef.h>
#include <stdint.h>

enum FieldFlags
{
	FLAG_NONE = 0,
	FLAG_DETAIL,
	FLAG_STATEMENT,
	FLAG_HINT,
	FLAG_QUERY,
	FLAG_CONTEXT,
	FLAG_SCHEMA,
	FLAG_TABLE,
	FLAG_COLUMN,
	FLAG_DATATYPE,
	FLAG_CONSTRAINT,
	FLAG_PGUSER,
	FLAG_PGDATABASE,
	FLAG_PGHOST,
	FLAG_PGAPPNAME,
};

struct MessageId
{
	uint32_t flags;
	const char *id128;
};

extern struct MessageId pgj_message_ids[];
extern const size_t pgj_message_ids_count;

extern const char *pgj_id128_log_statement;

#endif //PG_JOURNAL_PG_JOURNAL_IDS_H
