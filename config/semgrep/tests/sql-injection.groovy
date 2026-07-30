/**
 * Semgrep test fixtures for openboxes-sql-injection.yml rules.
 *
 * Positive fixtures (// ruleid: <rule-id>) mark lines that MUST be flagged.
 * Negative fixtures (// ok: <rule-id>) mark lines that must NOT be flagged.
 *
 * Run with:
 *   semgrep --test --config config/semgrep/ config/semgrep/tests/
 *
 * NOTE: No real credential or sensitive value appears in this file.
 * All values are synthetic test placeholders.
 */

// ─── Rule: groovy-gstring-sql-method-interpolation ──────────────────────────

class SqlInjectionPositiveFixtures {

    // Positive: direct GString interpolation into sql.eachRow argument
    // ruleid: groovy-gstring-sql-method-interpolation
    def badEachRow(sql, params) { sql.eachRow("SELECT name FROM product WHERE id = ${params.id}") }

    // Positive: direct GString interpolation into sql.rows argument
    // ruleid: groovy-gstring-sql-method-interpolation
    def badRows(sql, id) { sql.rows("SELECT * FROM shipment WHERE shipment_id = ${id}") }

    // Positive: direct GString interpolation into sql.executeQuery argument
    // ruleid: groovy-gstring-sql-method-interpolation
    def badExecuteQuery(sql, id) { sql.executeQuery("SELECT * FROM order_item WHERE order_id = ${id}") }

    // Positive: direct GString interpolation into sql.executeUpdate argument
    // ruleid: groovy-gstring-sql-method-interpolation
    def badExecuteUpdate(sql, status) { sql.executeUpdate("UPDATE shipment SET status = '${status}' WHERE id = 1") }

    // Negative: parameterised query with ? placeholder — no GString interpolation
    // ok: groovy-gstring-sql-method-interpolation
    def goodRows(sql, id) { sql.rows("SELECT * FROM shipment WHERE id = ?", [id]) }

    // Negative: parameterised query with named parameter
    // ok: groovy-gstring-sql-method-interpolation
    def goodExecuteQuery(sql, id) { sql.executeQuery("SELECT * FROM order_item WHERE order_id = :id", [id: id]) }
}


// ─── Rule: groovy-gstring-sql-string-literal ────────────────────────────────

class SqlStringLiteralPositiveFixtures {

    // Positive: table.column = '${...}' — matches OrderSummaryService pattern
    //           AND `order`.id = '${orderId}'
    // ruleid: groovy-gstring-sql-string-literal
    String buildQueryBad1(String orderId) { return "SELECT * FROM orders WHERE order.id = '${orderId}'" }

    // Positive: table.column = ${...} without quotes — matches ShipmentController pattern
    //           and shipment.id = ${params.id}
    // ruleid: groovy-gstring-sql-string-literal
    String buildQueryBad2(String id) { return "SELECT * FROM t WHERE shipment.id = ${id}" }

    // Positive: backtick-quoted table reference — exact OrderSummaryService shape
    // ruleid: groovy-gstring-sql-string-literal
    String buildQueryBad3(String orderId) { return "AND `order`.id = '${orderId}'" }

    // Negative: parameterised SQL with named :param placeholder — no interpolation
    // ok: groovy-gstring-sql-string-literal
    String buildQueryGood1(String orderId) { return "SELECT * FROM orders WHERE order.id = :orderId" }

    // Negative: log statement using English 'or' — no dot-notation before =
    // ok: groovy-gstring-sql-string-literal
    String logGood(String name) { log.info "find or create location name=${name}" }

    // Negative: SQL without interpolation — static query
    // ok: groovy-gstring-sql-string-literal
    String buildQueryGood2() { return "SELECT * FROM orders WHERE order.status = 'PENDING'" }
}


// ─── Rule: groovy-hibernate-gstring-interpolation ───────────────────────────

class HibernateGStringPositiveFixtures {

    // Positive: GString interpolation into createSQLQuery
    // ruleid: groovy-hibernate-gstring-interpolation
    def badCreateSQLQuery(session, id) { session.createSQLQuery("SELECT * FROM product WHERE id = ${id}") }

    // Positive: GString interpolation into createQuery (HQL)
    // ruleid: groovy-hibernate-gstring-interpolation
    def badCreateQuery(session, name) { session.createQuery("FROM Product WHERE name = '${name}'") }

    // Negative: named parameter binding in createSQLQuery
    // ok: groovy-hibernate-gstring-interpolation
    def goodCreateSQLQuery(session, id) { session.createSQLQuery("SELECT * FROM product WHERE id = :id").setString("id", id) }

    // Negative: named parameter in createQuery (HQL)
    // ok: groovy-hibernate-gstring-interpolation
    def goodCreateQuery(session, name) { session.createQuery("FROM Product WHERE name = :name").setString("name", name) }
}
