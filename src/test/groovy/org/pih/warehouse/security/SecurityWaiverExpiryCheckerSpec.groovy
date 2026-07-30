/**
 * Copyright (c) 2024 Partners In Health.  All rights reserved.
 * The use and distribution terms for this software are covered by the
 * Eclipse Public License 1.0 (http://opensource.org/licenses/eclipse-1.0.php)
 * which can be found in the file epl-v10.html at the root of this distribution.
 * By using this software in any fashion, you are agreeing to be bound by
 * the terms of this license.
 * You must not remove this notice, or any other, from this software.
 */
package org.pih.warehouse.security

import spock.lang.Specification
import spock.lang.Unroll

import java.time.LocalDate

import org.pih.warehouse.security.SecurityWaiverExpiryChecker
import org.pih.warehouse.security.SecurityWaiverExpiryChecker.CheckResult

/**
 * Unit tests for {@link SecurityWaiverExpiryChecker}.
 *
 * Covers:
 *   - Valid allowlist entries: should pass
 *   - Expired entries: should fail with a clear message
 *   - Missing required fields: should fail
 *   - Malformed expiry dates: should fail
 *   - Non-existent file: should fail
 *   - Both YAML and JSON parsing
 */
class SecurityWaiverExpiryCheckerSpec extends Specification {

    static final LocalDate REFERENCE_DATE = LocalDate.of(2026, 7, 30)

    // ── YAML parsing ─────────────────────────────────────────────────────────

    void 'checkAllowlist should pass when all entries are valid and not expired'() {
        given: 'An allowlist file with two valid, non-expired entries'
        File file = tempYamlFile('''
entries:
  - id: "TEST-001"
    tool: semgrep
    ruleId: "some-rule"
    file: "src/Foo.groovy"
    owner: "platform-team"
    justification: "Known pre-existing finding."
    expiryDate: "2027-01-01"
    remediationStory: "WO-001"
  - id: "TEST-002"
    tool: gitleaks
    ruleId: "generic-api-key"
    file: "config/app.yml"
    owner: "security-team"
    justification: "Widget key, not a backend secret."
    expiryDate: "2027-06-30"
    remediationStory: "WO-002"
''')

        when:
        CheckResult result = SecurityWaiverExpiryChecker.checkAllowlist(file, REFERENCE_DATE)

        then:
        result.ok
        result.violations.isEmpty()
        result.message.contains('2')
    }

    void 'checkAllowlist should fail when an entry has an expired expiryDate'() {
        given: 'An allowlist file with one expired entry'
        File file = tempYamlFile('''
entries:
  - id: "EXPIRED-001"
    tool: semgrep
    ruleId: "some-rule"
    file: "src/Foo.groovy"
    owner: "platform-team"
    justification: "Expired suppression."
    expiryDate: "2025-12-31"
    remediationStory: "WO-001"
''')

        when:
        CheckResult result = SecurityWaiverExpiryChecker.checkAllowlist(file, REFERENCE_DATE)

        then:
        !result.ok
        result.violations.size() == 1
        result.violations[0].contains('EXPIRED-001')
        result.violations[0].contains('EXPIRED')
        result.violations[0].contains('2025-12-31')
        result.violations[0].contains('platform-team')
    }

    void 'checkAllowlist should fail when an entry expires on the reference date itself'() {
        given: 'An entry expiring exactly on the reference date (today)'
        File file = tempYamlFile("""
entries:
  - id: "TODAY-001"
    tool: semgrep
    ruleId: "some-rule"
    file: "src/Foo.groovy"
    owner: "platform-team"
    justification: "Expiring today."
    expiryDate: "${REFERENCE_DATE}"
    remediationStory: "WO-001"
""")

        when:
        CheckResult result = SecurityWaiverExpiryChecker.checkAllowlist(file, REFERENCE_DATE)

        then:
        !result.ok
        result.violations[0].contains('TODAY-001')
        result.violations[0].contains('EXPIRED')
    }

    void 'checkAllowlist should fail when a required field is missing'() {
        given: 'An entry missing the owner field'
        File file = tempYamlFile('''
entries:
  - id: "MISSING-001"
    tool: semgrep
    ruleId: "some-rule"
    file: "src/Foo.groovy"
    justification: "No owner supplied."
    expiryDate: "2027-01-01"
''')

        when:
        CheckResult result = SecurityWaiverExpiryChecker.checkAllowlist(file, REFERENCE_DATE)

        then:
        !result.ok
        result.violations.any { it.contains('owner') && it.contains('MISSING-001') }
    }

    @Unroll
    void 'checkAllowlist should fail when required field "#field" is absent'() {
        given:
        String yaml = buildMinimalEntry([id: 'X-001', tool: 'semgrep', owner: 'team', justification: 'j', expiryDate: '2027-01-01'])
        String modified = yaml.replace("    ${field}:", "    _disabled_${field}:")
        File file = tempYamlFile(modified)

        when:
        CheckResult result = SecurityWaiverExpiryChecker.checkAllowlist(file, REFERENCE_DATE)

        then:
        !result.ok
        result.violations.any { it.contains(field) }

        where:
        field << ['id', 'tool', 'owner', 'justification', 'expiryDate']
    }

    void 'checkAllowlist should fail when expiryDate is malformed'() {
        given: 'An entry with an unparseable expiryDate'
        File file = tempYamlFile('''
entries:
  - id: "BAD-DATE-001"
    tool: semgrep
    ruleId: "some-rule"
    file: "src/Foo.groovy"
    owner: "platform-team"
    justification: "Bad date format."
    expiryDate: "31/12/2027"
    remediationStory: "WO-001"
''')

        when:
        CheckResult result = SecurityWaiverExpiryChecker.checkAllowlist(file, REFERENCE_DATE)

        then:
        !result.ok
        result.violations.any { it.contains('BAD-DATE-001') && it.contains('invalid expiryDate') }
    }

    void 'checkAllowlist should return an error when the file does not exist'() {
        given:
        File nonExistent = new File('/tmp/does-not-exist-allowlist.yml')

        when:
        CheckResult result = SecurityWaiverExpiryChecker.checkAllowlist(nonExistent, REFERENCE_DATE)

        then:
        !result.ok
        result.message.contains('not found')
    }

    void 'checkAllowlist should pass for an empty entries list'() {
        given:
        File file = tempYamlFile('''
entries:
''')

        when:
        CheckResult result = SecurityWaiverExpiryChecker.checkAllowlist(file, REFERENCE_DATE)

        then:
        result.ok
    }

    // ── JSON parsing ─────────────────────────────────────────────────────────

    void 'checkAllowlist should parse a JSON file with a top-level entries array'() {
        given:
        File file = tempJsonFile('''{
  "entries": [
    {
      "id": "JSON-001",
      "tool": "gitleaks",
      "ruleId": "generic-api-key",
      "file": "config/app.yml",
      "owner": "platform-team",
      "justification": "Widget key baseline.",
      "expiryDate": "2027-01-01",
      "remediationStory": "WO-002"
    }
  ]
}''')

        when:
        CheckResult result = SecurityWaiverExpiryChecker.checkAllowlist(file, REFERENCE_DATE)

        then:
        result.ok
        result.violations.isEmpty()
    }

    void 'checkAllowlist should fail for an expired entry in a JSON file'() {
        given:
        File file = tempJsonFile('''{
  "entries": [
    {
      "id": "JSON-EXPIRED-001",
      "tool": "gitleaks",
      "ruleId": "generic-api-key",
      "file": "config/app.yml",
      "owner": "platform-team",
      "justification": "Expired.",
      "expiryDate": "2020-01-01"
    }
  ]
}''')

        when:
        CheckResult result = SecurityWaiverExpiryChecker.checkAllowlist(file, REFERENCE_DATE)

        then:
        !result.ok
        result.violations.any { it.contains('JSON-EXPIRED-001') && it.contains('EXPIRED') }
    }

    // ── Mixed valid and expired ───────────────────────────────────────────────

    void 'checkAllowlist should report ALL expired entries when multiple are present'() {
        given:
        File file = tempYamlFile('''
entries:
  - id: "VALID-001"
    tool: semgrep
    ruleId: "rule-a"
    file: "src/A.groovy"
    owner: "team-a"
    justification: "Valid."
    expiryDate: "2028-01-01"
  - id: "EXPIRED-A"
    tool: semgrep
    ruleId: "rule-b"
    file: "src/B.groovy"
    owner: "team-b"
    justification: "Expired first."
    expiryDate: "2023-06-01"
  - id: "EXPIRED-B"
    tool: gitleaks
    ruleId: "secret-rule"
    file: "config/c.yml"
    owner: "team-c"
    justification: "Expired second."
    expiryDate: "2024-12-31"
''')

        when:
        CheckResult result = SecurityWaiverExpiryChecker.checkAllowlist(file, REFERENCE_DATE)

        then:
        !result.ok
        result.violations.size() == 2
        result.violations.any { it.contains('EXPIRED-A') }
        result.violations.any { it.contains('EXPIRED-B') }
        !result.violations.any { it.contains('VALID-001') }
    }

    // ── Real allowlist file integration smoke-test ────────────────────────────

    void 'checkAllowlist passes against the committed allowlist file on the reference date'() {
        given: 'The real committed allowlist from the repository'
        File realAllowlist = new File('config/semgrep/allowlist.yml')

        // Only run if the file actually exists relative to the working directory.
        // (Allows this test to pass when the CWD is not the repository root.)
        if (!realAllowlist.exists()) {
            return
        }

        when:
        // Run against a reference date well before all committed expiry dates.
        CheckResult result = SecurityWaiverExpiryChecker.checkAllowlist(realAllowlist, LocalDate.of(2026, 7, 30))

        then:
        result.ok
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static File tempYamlFile(String content) {
        File f = File.createTempFile('allowlist-test-', '.yml')
        f.deleteOnExit()
        f.text = content.stripIndent()
        return f
    }

    private static File tempJsonFile(String content) {
        File f = File.createTempFile('allowlist-test-', '.json')
        f.deleteOnExit()
        f.text = content
        return f
    }

    private static String buildMinimalEntry(Map fields) {
        // Use "  - " on its own line so every field uses the same "    key: value"
        // format, making yaml.replace("    key:", ...) work uniformly for all fields
        // including 'id'.
        StringBuilder sb = new StringBuilder('entries:\n  - \n')
        fields.each { k, v ->
            sb << "    ${k}: \"${v}\"\n"
        }
        return sb.toString()
    }


}
