"""SQL Parser using SQLGlot for semantic AST feature extraction."""
from typing import Dict, Any, List, Set, Optional
import sqlglot
from sqlglot import exp

class SQLSemanticParser:
    """Extracts structural and semantic security features from raw SQL text."""

    @staticmethod
    def parse_query(sql_text: Optional[str]) -> Dict[str, Any]:
        """Safely parses a SQL query into structural security indicators."""
        default_res: Dict[str, Any] = {
            "is_valid_sql": False,
            "query_type": "UNKNOWN",
            "is_select": 0,
            "is_dml": 0,
            "is_ddl": 0,
            "has_join": 0,
            "has_where": 0,
            "has_subquery": 0,
            "has_wildcard": 0,
            "is_dangerous": 0,
            "query_complexity": 0,
            "referenced_tables": [],
            "referenced_columns": []
        }
        
        if not sql_text or not isinstance(sql_text, str) or not sql_text.strip():
            return default_res

        cleaned_sql = sql_text.strip()
        upper_raw = cleaned_sql.upper()

        parsed = None
        for dialect in ["sqlite", "postgres", "mysql", None]:
            try:
                parsed = sqlglot.parse_one(cleaned_sql, read=dialect)
                if parsed:
                    break
            except Exception:
                continue

        if parsed is None:
            # Fall back to regex/heuristic detection safely
            q_type = upper_raw.split()[0] if upper_raw.split() else "UNKNOWN"
            default_res["query_type"] = q_type
            default_res["is_select"] = 1 if "SELECT" in upper_raw else 0
            default_res["is_ddl"] = 1 if any(w in upper_raw for w in ["DROP", "TRUNCATE", "ALTER"]) else 0
            default_res["is_dangerous"] = 1 if any(w in upper_raw for w in ["DROP", "TRUNCATE", "OR '1'='1'"]) else 0
            return default_res

        # Determine AST Type
        ast_type_name = type(parsed).__name__.upper()
        if isinstance(parsed, exp.Select):
            query_type = "SELECT"
        elif isinstance(parsed, exp.Insert):
            query_type = "INSERT"
        elif isinstance(parsed, exp.Update):
            query_type = "UPDATE"
        elif isinstance(parsed, exp.Delete):
            query_type = "DELETE"
        elif isinstance(parsed, exp.Drop) or "DROP" in ast_type_name:
            query_type = "DROP"
        elif "TRUNCATE" in ast_type_name:
            query_type = "TRUNCATE"
        elif isinstance(parsed, (exp.Create, exp.Alter)) or any(d in ast_type_name for d in ["CREATE", "ALTER", "DDL"]):
            query_type = "DDL"
        else:
            query_type = ast_type_name

        is_select = 1 if query_type == "SELECT" else 0
        is_dml = 1 if query_type in ["INSERT", "UPDATE", "DELETE"] else 0
        is_ddl = 1 if query_type in ["DROP", "TRUNCATE", "ALTER", "CREATE", "DDL"] else 0

        # Tables
        tables: Set[str] = set()
        for table in parsed.find_all(exp.Table):
            if table.name:
                tables.add(table.name.lower())

        # Columns
        columns: Set[str] = set()
        for col in parsed.find_all(exp.Column):
            if col.name:
                columns.add(col.name.lower())

        # Structural flags
        has_join = 1 if list(parsed.find_all(exp.Join)) else 0
        has_where = 1 if parsed.find(exp.Where) is not None else 0
        
        # Subquery presence
        subqueries = [sq for sq in parsed.find_all(exp.Select) if sq is not parsed]
        has_subquery = 1 if len(subqueries) > 0 else 0

        # Wildcard selection
        has_wildcard = 1 if list(parsed.find_all(exp.Star)) else 0

        # Query complexity heuristic: total AST nodes
        ast_nodes = len(list(parsed.walk()))
        query_complexity = min(50, ast_nodes)

        # Dangerous command heuristic
        is_dangerous = 0
        if query_type in ["DROP", "TRUNCATE"] or "DROP" in upper_raw or "TRUNCATE" in upper_raw:
            is_dangerous = 1
        elif query_type == "DELETE" and not has_where:
            is_dangerous = 1
        elif "OR '1'='1'" in upper_raw or "OR 1=1" in upper_raw or "UNION SELECT" in upper_raw:
            is_dangerous = 1

        return {
            "is_valid_sql": True,
            "query_type": query_type,
            "is_select": is_select,
            "is_dml": is_dml,
            "is_ddl": is_ddl,
            "has_join": has_join,
            "has_where": has_where,
            "has_subquery": has_subquery,
            "has_wildcard": has_wildcard,
            "is_dangerous": is_dangerous,
            "query_complexity": query_complexity,
            "referenced_tables": sorted(list(tables)),
            "referenced_columns": sorted(list(columns))
        }
