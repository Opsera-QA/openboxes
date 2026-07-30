package org.pih.warehouse.build

import spock.lang.Specification
import spock.lang.Unroll

import java.time.LocalDate

/**
 * Unit tests for {@link SuppressionExpiryChecker}.
 *
 * Fixture XML files are located under
 * {@code src/test/resources/suppressions/} and are read from the classpath.
 */
class SuppressionExpiryCheckerSpec extends Specification {

    private static final LocalDate REFERENCE_DATE = LocalDate.of(2026, 7, 30)

    private SuppressionExpiryChecker checker = new SuppressionExpiryChecker()

    // -------------------------------------------------------------------------
    // helpers
    // -------------------------------------------------------------------------

    private String loadFixture(String filename) {
        URL resource = getClass().getResource("/suppressions/${filename}")
        assert resource != null : "Fixture file not found on classpath: /suppressions/${filename}"
        return resource.text
    }

    // -------------------------------------------------------------------------
    // valid waivers
    // -------------------------------------------------------------------------

    def "all future-dated waivers are accepted"() {
        given:
        String xml = loadFixture('valid-suppressions.xml')

        when:
        List<SuppressionExpiryChecker.ExpiredEntry> result = checker.findExpiredEntries(xml, REFERENCE_DATE)

        then:
        result.isEmpty()
    }

    // -------------------------------------------------------------------------
    // expired waivers
    // -------------------------------------------------------------------------

    def "all past-dated waivers are reported as expired"() {
        given:
        String xml = loadFixture('expired-suppressions.xml')

        when:
        List<SuppressionExpiryChecker.ExpiredEntry> result = checker.findExpiredEntries(xml, REFERENCE_DATE)

        then:
        result.size() == 2
        result.every { it.reason.contains('expired') }
    }

    @Unroll
    def "waiver expiring on #expiryDate is #expectedOutcome when reference date is #referenceDate"() {
        given:
        String xml = """<?xml version="1.0" encoding="UTF-8"?>
<suppressions>
    <suppress>
        <notes><![CDATA[
owner: test-owner
reason: Inline test waiver.
expires: ${expiryDate}
        ]]></notes>
        <cve>CVE-2020-99999</cve>
    </suppress>
</suppressions>"""

        when:
        List<SuppressionExpiryChecker.ExpiredEntry> result =
            checker.findExpiredEntries(xml, LocalDate.parse(referenceDate))

        then:
        result.isEmpty() == shouldPass

        where:
        expiryDate   | referenceDate | shouldPass | expectedOutcome
        '2099-12-31' | '2026-07-30'  | true       | 'accepted (far future)'
        '2026-07-31' | '2026-07-30'  | true       | 'accepted (expires tomorrow)'
        '2026-07-30' | '2026-07-30'  | false      | 'rejected (expires today)'
        '2026-07-29' | '2026-07-30'  | false      | 'rejected (expired yesterday)'
        '2020-01-01' | '2026-07-30'  | false      | 'rejected (expired long ago)'
    }

    // -------------------------------------------------------------------------
    // missing expiry
    // -------------------------------------------------------------------------

    def "waivers without an expires line are all rejected"() {
        given:
        String xml = loadFixture('missing-expiry-suppressions.xml')

        when:
        List<SuppressionExpiryChecker.ExpiredEntry> result = checker.findExpiredEntries(xml, REFERENCE_DATE)

        then:
        // All three suppress entries lack an expires: line
        result.size() == 3
        result.every { it.expiryDate == null }
        result.every { it.reason.contains('expires') }
    }

    def "a suppress entry with no notes element is rejected"() {
        given:
        String xml = """<?xml version="1.0" encoding="UTF-8"?>
<suppressions>
    <suppress>
        <cve>CVE-2020-99999</cve>
    </suppress>
</suppressions>"""

        when:
        List<SuppressionExpiryChecker.ExpiredEntry> result = checker.findExpiredEntries(xml, REFERENCE_DATE)

        then:
        result.size() == 1
        result[0].expiryDate == null
    }

    // -------------------------------------------------------------------------
    // identifier resolution
    // -------------------------------------------------------------------------

    @Unroll
    def "identifier is resolved from #elementType coordinate"() {
        given:
        String xml = """<?xml version="1.0" encoding="UTF-8"?>
<suppressions>
    <suppress>
        <notes><![CDATA[
owner: test-owner
reason: Identifier resolution test.
expires: 2099-12-31
        ]]></notes>
        ${coordinateXml}
    </suppress>
</suppressions>"""

        when:
        List<SuppressionExpiryChecker.ExpiredEntry> result = checker.findExpiredEntries(xml, REFERENCE_DATE)

        then:
        // Waiver is valid (future date), so the list is empty — identifier resolved without error
        result.isEmpty()

        where:
        elementType   | coordinateXml
        'CVE'         | '<cve>CVE-2020-99999</cve>'
        'filePath'    | '<filePath regex="true">.*some-lib\\.jar</filePath>'
        'GAV'         | '<gav regex="true">.*:some-library:.*</gav>'
        'packageUrl'  | '<packageUrl regex="true">pkg:npm/some-package@.*</packageUrl>'
    }

    // -------------------------------------------------------------------------
    // malformed XML — must throw, never fail open
    // -------------------------------------------------------------------------

    def "malformed XML causes a RuntimeException (fail loud, not fail open)"() {
        given:
        String xml = loadFixture('malformed-suppressions.xml')

        when:
        checker.findExpiredEntries(xml, REFERENCE_DATE)

        then:
        RuntimeException ex = thrown(RuntimeException)
        ex.message.contains('Malformed suppression file')
    }

    def "completely empty string causes a RuntimeException"() {
        when:
        checker.findExpiredEntries('', REFERENCE_DATE)

        then:
        thrown(RuntimeException)
    }

    // -------------------------------------------------------------------------
    // malformed expires date
    // -------------------------------------------------------------------------

    def "a non-ISO expiry date causes a RuntimeException"() {
        given:
        String xml = """<?xml version="1.0" encoding="UTF-8"?>
<suppressions>
    <suppress>
        <notes><![CDATA[
owner: test-owner
reason: Bad date format.
expires: 30/07/2026
        ]]></notes>
        <cve>CVE-2020-99999</cve>
    </suppress>
</suppressions>"""

        when:
        checker.findExpiredEntries(xml, REFERENCE_DATE)

        then:
        RuntimeException ex = thrown(RuntimeException)
        ex.message.contains('Malformed expiry date')
    }

    // -------------------------------------------------------------------------
    // empty suppression file
    // -------------------------------------------------------------------------

    def "a valid but empty suppression file with no suppress entries returns an empty list"() {
        given:
        String xml = """<?xml version="1.0" encoding="UTF-8"?>
<suppressions>
</suppressions>"""

        when:
        List<SuppressionExpiryChecker.ExpiredEntry> result = checker.findExpiredEntries(xml, REFERENCE_DATE)

        then:
        result.isEmpty()
    }
}
