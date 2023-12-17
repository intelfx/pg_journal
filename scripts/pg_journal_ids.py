#!/usr/bin/env python3
import sys
import enum
import itertools
import uuid
from typing import (
	Iterable,
	TypeAlias,
	assert_never,
)

class UUID(enum.Enum):
	# Namespace UUID for message IDs
	Namespace = uuid.uuid5(uuid.NAMESPACE_URL, 'https://github.com/intelfx/pg_journal')
	assert Namespace == uuid.UUID('27d0a4fe-7671-5e96-99af-621ddd626c21')

	# Legacy UUID used for log_statement messages
	LogStatement = uuid.UUID('a6369936-8b30-4b4c-b51b-ce5644736306')

	@classmethod
	def from_fields(cls, fields: tuple[str, ...]) -> uuid.UUID:
		return uuid.uuid5(namespace=cls.Namespace.value, name=str(sorted(fields)))


Node: TypeAlias = 'str|AllOf|CombinationOf|AnyOf'

class AllOf(tuple[Node, ...]):
	def __new__(cls, *args: Node):
		return super().__new__(cls, args)

class CombinationOf(tuple[Node, ...]):
	def __new__(cls, *args: Node):
		return super().__new__(cls, args)

class AnyOf(tuple[Node, ...]):
	def __new__(cls, *args: Node):
		return super().__new__(cls, args)


FIELDS: Node = CombinationOf(
	'DETAIL',
	'HINT',
	'QUERY',
	'CONTEXT',
	'STATEMENT',
	AnyOf(
		AllOf('SCHEMA', 'TABLE'),
		AllOf('SCHEMA', 'TABLE', 'CONSTRAINT'),
		AllOf('SCHEMA', 'TABLE', 'COLUMN'),
		AllOf('SCHEMA', 'DATATYPE'),
		AllOf('SCHEMA', 'DATATYPE', 'CONSTRAINT'),
	),
	CombinationOf(
		AllOf('PGUSER', 'PGHOST', 'PGDATABASE'),
		'PGAPPNAME',
	),
)


def visit(items: tuple[str, ...], node: Node) -> Iterable[tuple[str, ...]]:
	if isinstance(node, str):
		yield items + (node, )
	elif isinstance(node, AllOf):
		if len(node) == 0:
			yield items
		elif all(isinstance(t, str) for t in node):
			yield items + node
		elif len(node) == 1:
			yield from visit(items, node[0])
		else:
			for o in visit(items, node[0]):
				yield from visit(o, AllOf(*node[1:]))
	elif isinstance(node, AnyOf):
		yield items
		for i in node:
			yield from visit(items, i)
	elif isinstance(node, CombinationOf):
		for L in range(0, len(node) + 1):
			for c in itertools.combinations(node, L):
				yield from visit(items, AllOf(*c))
	else:
		assert_never(node)


def generate() -> dict[tuple[str, ...]]:
	return dict.fromkeys(visit((), FIELDS))


def generate_list() -> list[tuple[str, ...]]:
	return list(generate().keys())


def check_fields(fields: tuple[str, ...]) -> bool:
	if 'QUERY' in fields and 'STATEMENT' in fields:
		return False
	return True


def main():
	keys = generate_list()
	print(f'Generated {len(keys)} items')

	# add UUIDs, filter items
	items = {
		fields: UUID.from_fields(fields)
		for fields in keys
		if check_fields(fields)
	}

	# generate lookup table
	lookup_items: list[str] = []
	for fields, id128 in items.items():
		flags = ' | '.join(
			f'(1 << FLAG_{field})'
			for field
			in fields
		) if fields else '0'
		lookup_items.append(
			f'\t{{ .flags = {flags},\n'
			f'\t  .id128 = "{id128.hex}" }}'
		)

	print(f'Generated {len(lookup_items)} message ID lookup table entries')
	with open('src/pg_journal_ids.c', 'w') as f:
		f.write((r'''
#include "pg_journal_ids.h"

struct MessageId pgj_message_ids[] = {
''' + ',\n'.join(lookup_items) + r'''
};
const size_t pgj_message_ids_count = sizeof(pgj_message_ids) / sizeof(pgj_message_ids[0]);
const char *pgj_id128_log_statement = "''' + UUID.LogStatement.value.hex + r'''";
''')[1:])  # strip leading \n

	# Generate catalog
	catalog_items: list[str] = []
	for fields, id128 in items.items():
		if not fields:
			continue

		desc = []
		connstring = []
		for field in fields:
			if field == 'PGUSER':
				connstring.append(f'user=@PGUSER@')
			elif field == 'PGHOST':
				connstring.append(f'host=@PGHOST@')
			elif field == 'PGDATABASE':
				connstring.append(f'dbname=@PGDATABASE@')
			elif field == 'PGAPPNAME':
				connstring = [ f'(@PGAPPNAME@)' ] + connstring
			else:
				desc.append(f'{field}: @{field}@')

		if connstring:
			desc.append(f'CONNECTION: {" ".join(connstring)}')

		catalog_items.append(
			f'-- {id128.hex}\n' + '\n'.join(desc) + '\n'
		)

	print(f'Generated {len(catalog_items)} journal catalog entries')
	with open('src/pg_journal_ids.catalog', 'w') as f:
		f.write((r'''
# This is the catalog for pg_journal extension

''' + '\n'.join(catalog_items) + r'''
''')[1:])  # strip leading \n


def main_timeit():
	import timeit
	return timeit.main([
		'sys.modules["__main__"].generate_list()'
	])


if __name__ == '__main__':
	if sys.argv[1:] == ['timeit']:
		sys.exit(main_timeit())

	main()
