from django.db import NotSupportedError
from django.db.models.sql import compiler


class SQLCompiler(compiler.SQLCompiler):
    def as_sql(self, with_limits=True, with_col_aliases=False):
        """
        Create the SQL for this query. Return the SQL string and list
        of parameters.  This is overridden from the original Query class
        to handle the additional SQL Oracle requires to emulate LIMIT
        and OFFSET.

        If 'with_limits' is False, any limit/offset information is not
        included in the query.
        """
        # The `do_offset` flag indicates whether we need to construct
        # the SQL needed to use limit/offset with Oracle.
        do_offset = with_limits and (self.query.high_mark is not None or self.query.low_mark)
        if not do_offset:
            sql, params = super().as_sql(with_limits=False, with_col_aliases=with_col_aliases)
        elif not self.connection.features.supports_select_for_update_with_limit and self.query.select_for_update:
            raise NotSupportedError(
                'LIMIT/OFFSET is not supported with select_for_update on this '
                'database backend.'
            )
        else:
            sql, params = super().as_sql(with_limits=False, with_col_aliases=True)
            # Wrap the base query in an outer SELECT * with boundaries on
            # the "_RN" column.  This is the canonical way to emulate LIMIT
            # and OFFSET on Oracle.
            sql_where = 'WHERE '
            sql_where_list = []
            if self.query.high_mark is not None:
                sql_where_list.append('"_RN" <= %d' % (self.query.high_mark,))
            if self.query.low_mark is not None:
                sql_where_list.append('"_RN" > %d' % (self.query.low_mark,))
            sql_where += ' AND '.join(sql_where_list)
            sql = (
                'SELECT "__SUB".* FROM (SELECT "_SUB".*,ROWNUM AS "_RN" FROM (%s) "_SUB") "__SUB" %s' % (
                    sql, sql_where
                )
            )

        return sql, params


class SQLInsertCompiler(compiler.SQLInsertCompiler, SQLCompiler):
    pass


class SQLDeleteCompiler(compiler.SQLDeleteCompiler, SQLCompiler):
    pass


class SQLUpdateCompiler(compiler.SQLUpdateCompiler, SQLCompiler):
    pass


class SQLAggregateCompiler(compiler.SQLAggregateCompiler, SQLCompiler):
    pass
