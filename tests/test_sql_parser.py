"""Tests for SQL Semantic Parsing with SQLGlot."""
import pytest
from app.processing.sql_parser import SQLSemanticParser

def test_select_query_parsing():
    sql = "SELECT id, name, email FROM customers WHERE active = 1 AND balance > 500;"
    res = SQLSemanticParser.parse_query(sql)
    assert res["is_valid_sql"] is True
    assert res["query_type"] == "SELECT"
    assert res["is_select"] == 1
    assert res["has_where"] == 1
    assert res["has_join"] == 0
    assert "customers" in res["referenced_tables"]

def test_join_and_subquery_parsing():
    sql = """
    SELECT o.id, c.name FROM orders o 
    JOIN customers c ON o.customer_id = c.id 
    WHERE o.total > (SELECT AVG(total) FROM orders);
    """
    res = SQLSemanticParser.parse_query(sql)
    assert res["has_join"] == 1
    assert res["has_subquery"] == 1
    assert "orders" in res["referenced_tables"]
    assert "customers" in res["referenced_tables"]

def test_dangerous_statements():
    sql_drop = "DROP TABLE audit_log;"
    res_drop = SQLSemanticParser.parse_query(sql_drop)
    assert res_drop["is_dangerous"] == 1
    assert res_drop["is_ddl"] == 1

    sql_truncate = "TRUNCATE TABLE transactions;"
    res_trunc = SQLSemanticParser.parse_query(sql_truncate)
    assert res_trunc["is_dangerous"] == 1

    sql_unconstrained_del = "DELETE FROM orders;"
    res_del = SQLSemanticParser.parse_query(sql_unconstrained_del)
    assert res_del["is_dangerous"] == 1
    assert res_del["has_where"] == 0

def test_wildcard_detection():
    sql = "SELECT * FROM system_credentials;"
    res = SQLSemanticParser.parse_query(sql)
    assert res["has_wildcard"] == 1

def test_malformed_sql_fallback():
    malformed = "NOT A REAL SQL STATEMENT AT ALL"
    res = SQLSemanticParser.parse_query(malformed)
    assert isinstance(res, dict)
    assert "query_type" in res

def test_empty_input_handling():
    assert SQLSemanticParser.parse_query("")["is_valid_sql"] is False
    assert SQLSemanticParser.parse_query(None)["is_valid_sql"] is False
