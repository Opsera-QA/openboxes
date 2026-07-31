# Security Finding Remediation Backlog

This document records every pre-existing security finding that is currently
suppressed in the security-scanning baseline (`config/semgrep/allowlist.yml` and
`config/gitleaks-baseline.json`).  It is the **tracked debt list** that backs
the baseline — these are not silent suppressions but named, owned, dated items.

Every entry here corresponds to a record in `config/semgrep/allowlist.yml`.
When a finding is remediated, remove the corresponding entry from that file
AND from this document.

---

## A. SQL Injection (CWE-89)

### A1 — `ShipmentController.downloadPackingList` (SEMGREP-SHC-001)

| Field | Value |
|-------|-------|
| **File** | `grails-app/controllers/org/pih/warehouse/shipping/ShipmentController.groovy` |
| **Line** | ~693 |
| **Rule** | `groovy-gstring-sql-method-interpolation` |
| **Owner** | platform-team |
| **Expiry** | 2026-12-31 |
| **Remediation story** | WO-SECURITY-001 |

**Description**
The `downloadPackingList` action constructs a multi-line SQL string and
interpolates `params.id` (a raw request parameter) directly via GString
interpolation before passing it to `sql.eachRow(query)`.  A malicious `id`
value could escape the SQL context and execute arbitrary statements.

```groovy
// VULNERABLE — line ~677–693 of ShipmentController.groovy
String query = """
    select ...
    from shipment, container, shipment_item, product
    where ...
    and shipment.id = ${params.id}"""   // <-- params.id not sanitised
sql.eachRow(query) { row -> ... }
```

**Remediation**
Replace with a parameterised query:
```groovy
String query = "... and shipment.id = ?"
sql.eachRow(query, [params.id]) { row -> ... }
```

---

### A2 — `OrderSummaryService` SQL string interpolation (SEMGREP-OSS-001)

| Field | Value |
|-------|-------|
| **File** | `grails-app/services/org/pih/warehouse/order/OrderSummaryService.groovy` |
| **Lines** | ~26–376 (six methods) |
| **Rule** | `groovy-gstring-sql-string-literal` |
| **Owner** | platform-team |
| **Expiry** | 2026-12-31 |
| **Remediation story** | WO-SECURITY-001 |

**Description**
Six methods in `OrderSummaryService` build SQL fragments by interpolating an
`orderId` parameter directly into triple-quoted GStrings:

- `getOrderItemStatusSelect(orderId)`
- `getOrderItemReceiptStatusSelect(orderId)`
- `getOrderItemPaymentStatusSelect(orderId)`
- `getOrderItemSummarySelect(orderId)`
- `getOrderAdjustmentPaymentStatusSelect(orderId)`
- `getOrderSummarySelect(orderId)`

All six methods contain patterns such as:
```groovy
AND `order`.id = '${orderId}'
```

The assembled SQL is then passed to `dataService.executeQuery(...)`.

**Remediation**
Replace string interpolation with named JDBC parameters and update the callers
to pass a parameter map:
```groovy
// Before
return "... AND \`order\`.id = '${orderId}'"
// After
return "... AND \`order\`.id = :orderId"
// Callers: dataService.executeQuery(sql, [orderId: orderId])
```

---

## B. Mass Assignment (CWE-915)

> **Scope note (WO-004):** The `groovy-mass-assignment-properties-params` Semgrep rule
> detects ~98 instances of `.properties = params` across legacy controllers and services.
> The rule is set to **WARNING** severity (not ERROR) so that CI is not immediately broken
> before the remediation sprint runs.  All 98 sites are tracked debt; the highest-risk
> instance (AuthController.handleSignup) is the priority target for WO-SECURITY-001.
> The rule will be upgraded to ERROR severity once WO-SECURITY-001 reduces the count to zero.
>
> **Representative files with pre-existing instances:**
> `AuthController`, `CategoryApiController`, `DocumentController`, `BudgetCodeController`,
> `EventTypeController`, `GlAccountController`, `InventoryController`, `InventoryLevelController`,
> `OrderController`, `ProductController`, `ProductGroupController`, `RequisitionController`,
> `ShipmentController`, `ShipmentItemController`, `UserController`, `UserService`,
> and importer services (`LocationImportDataService`, `PersonImportDataService`,
> `ProductPackageImportDataService`, `UserImportDataService`, `ProductCatalogImportDataService`).

### B1 — `AuthController.handleSignup` (SEMGREP-AUTH-001) — highest-risk instance

| Field | Value |
|-------|-------|
| **File** | `grails-app/controllers/org/pih/warehouse/user/AuthController.groovy` |
| **Line** | ~175 |
| **Rule** | `groovy-mass-assignment-properties-params` (WARNING) |
| **Owner** | platform-team |
| **Expiry** | 2026-12-31 |
| **Remediation story** | WO-SECURITY-001 |

**Description**
`handleSignup` binds all request parameters onto a new `User` domain object via
`userInstance.properties = params`.  Although `active` is explicitly set to
`false` on the following line, other sensitive `User` fields (e.g. `username`,
any role-related fields) remain user-controllable.  This is the highest-risk
instance because it is on a public, unauthenticated endpoint.

**Remediation**
Replace with explicit allow-list binding:
```groovy
bindData(userInstance, params, [include: ['firstName', 'lastName', 'email', 'password', 'passwordConfirm']])
```

---

## C. Sensitive Data Logging (CWE-312)

### C1 — `JsonController` raw params logging (SEMGREP-JSON-001)

| Field | Value |
|-------|-------|
| **File** | `grails-app/controllers/org/pih/warehouse/JsonController.groovy` |
| **Lines** | 104, 137, 153, 187, 208, 236 |
| **Rule** | `groovy-raw-params-logging` |
| **Owner** | platform-team |
| **Expiry** | 2026-12-31 |
| **Remediation story** | WO-SECURITY-001 |

**Description**
Multiple action methods in `JsonController` log the full `params` map at INFO
level.  If a caller submits credentials or tokens as request parameters, they
will appear in the application log in cleartext.

**Remediation**
Replace `log.info "action: ${params}"` with logging of specific safe fields:
```groovy
log.info "addToRequisitionItems: requisitionId=${params.requisition?.id}, productId=${params.product?.id}"
```

---

## D. Embedded Third-Party Integration Keys (Secret Scanning)

### D1 — HelpScout Beacon widget key (GITLEAKS-GL-001)

| Field | Value |
|-------|-------|
| **File** | `grails-app/conf/application.yml` |
| **Line** | ~416 |
| **Rule** | `helpscout-beacon-key` (Gitleaks) |
| **Owner** | platform-team |
| **Expiry** | 2026-12-31 |
| **Remediation story** | WO-SECURITY-002 |

**Description**
The HelpScout Beacon widget key (`openboxes.helpscout.widget.key`) is a
client-side widget identifier embedded literally in `application.yml`.  It is
not a backend API credential (it grants no server-side access), but should be
moved to environment-variable injection so that key rotation does not require a
code change.

**Remediation**
Remove the literal value from `application.yml` and inject via an environment
variable:
```yaml
helpscout:
  widget:
    key: "${HELPSCOUT_BEACON_KEY:}"
```

---

### D2 — Zopim (Zendesk Chat) widget URL token (GITLEAKS-GL-002)

| Field | Value |
|-------|-------|
| **File** | `grails-app/conf/application.yml` |
| **Line** | ~409 |
| **Rule** | `zopim-widget-key` (Gitleaks) |
| **Owner** | platform-team |
| **Expiry** | 2026-12-31 |
| **Remediation story** | WO-SECURITY-002 |

**Description**
The Zopim (Zendesk Chat) widget URL (`openboxes.zopim.widget.url`) embeds a
client-side widget token.  The widget is disabled by default (`enabled: false`)
but the token is still committed in plaintext.

**Remediation**
Inject via environment variable:
```yaml
zopim:
  widget:
    url: "${ZOPIM_WIDGET_URL:}"
```

---

## How to Use This Backlog

1. **When a finding is remediated**: remove the entry from `config/semgrep/allowlist.yml`
   and from this document, and close the linked story.
2. **When an expiry needs extending**: update `expiryDate` in
   `config/semgrep/allowlist.yml` with explicit team approval, add a comment
   explaining the delay, and link the new target story.  Update this document
   accordingly.
3. **When a new pre-existing finding must be baselined**: add it to
   `config/semgrep/allowlist.yml` (with a future `expiryDate`, `owner`,
   `justification`, and `remediationStory`) AND add an entry here.

The `checkSecurityWaiverExpiry` Gradle task (`./gradlew checkSecurityWaiverExpiry`)
enforces that no `expiryDate` is in the past.  An expired entry fails CI.
