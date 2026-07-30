/**
 * Semgrep test fixtures for openboxes-mass-assignment.yml rules.
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

// ─── Rule: groovy-mass-assignment-properties-params ─────────────────────────

class MassAssignmentPositiveFixtures {

    // Positive: direct .properties = params assignment — matches AuthController.handleSignup pattern
    // ruleid: groovy-mass-assignment-properties-params
    def handleSignup(userInstance, params) { userInstance.properties = params }

    // Positive: chained on a domain instance
    // ruleid: groovy-mass-assignment-properties-params
    def updateItem(item, params) { item.properties = params; item.save() }

    // Negative: allow-list bindData — safe pattern
    // ok: groovy-mass-assignment-properties-params
    def handleSignupSafe(userInstance, params) { bindData(userInstance, params, [include: ['firstName', 'lastName', 'email']]) }

    // Negative: assigning to a non-params variable
    // ok: groovy-mass-assignment-properties-params
    def copyProperties(target, source) { target.properties = source.properties }
}


// ─── Rule: groovy-mass-assignment-properties-map-construction ───────────────

class MassAssignmentConstructionFixtures {

    // Positive: constructing a domain from another's properties map
    // ruleid: groovy-mass-assignment-properties-map-construction
    def cloneUser(original) { return new User(original.properties) }

    // Positive: constructing with explicit .properties access
    // ruleid: groovy-mass-assignment-properties-map-construction
    def cloneOrder(src) { return new Order(src.properties) }

    // Negative: explicit field-by-field construction
    // ok: groovy-mass-assignment-properties-map-construction
    def safeCloneUser(original) { return new User(name: original.name, email: original.email) }
}


// ─── Rule: groovy-raw-params-logging ────────────────────────────────────────

class RawParamsLoggingFixtures {

    // Positive: logging entire params map — matches JsonController pattern
    // ruleid: groovy-raw-params-logging
    def addItem(params) { log.info "addToRequisitionItems: ${params} " }

    // Positive: logging params using string concatenation
    // ruleid: groovy-raw-params-logging
    def getItems(params) { log.info "getRequisitionItems: " + params }

    // Positive: logging params with warn
    // ruleid: groovy-raw-params-logging
    def updateItem(params) { log.warn "updateRequisitionItems: ${params}" }

    // Negative: logging only a specific safe field
    // ok: groovy-raw-params-logging
    def safeLog(params) { log.info "Processing item id=${params.id}" }

    // Negative: logging a non-params variable named data
    // ok: groovy-raw-params-logging
    def safeLogData(data) { log.info "Result: ${data}" }
}
