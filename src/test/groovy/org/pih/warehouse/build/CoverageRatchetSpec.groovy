package org.pih.warehouse.build

import spock.lang.Specification
import spock.lang.Unroll

/**
 * Unit tests for {@link CoverageRatchet}.
 *
 * Fixture XML files live under src/test/resources/org/pih/warehouse/build/ and
 * are committed alongside the spec so the test is self-contained and reproducible
 * without a running database or a live Gradle build.
 *
 * Fixture files:
 *  - jacoco-high-coverage.xml   instruction=99.00%, branch=95.00%
 *  - jacoco-low-coverage.xml    instruction=10.00%, branch=20.00%
 *  - jacoco-malformed.xml       broken XML that cannot be parsed
 *  - jacoco-zero-counters.xml   valid XML with no counter elements
 *  - baseline-high.properties   instruction=98.5%, branch=94.5%, tolerance=0.5
 *  - baseline-low.properties    instruction=9.0%,  branch=18.0%, tolerance=0.5
 */
class CoverageRatchetSpec extends Specification {

    CoverageRatchet ratchet = new CoverageRatchet()

    // ── parse() ───────────────────────────────────────────────────────────────

    void 'parse should correctly extract instruction and branch percentages from high-coverage fixture'() {
        given:
        InputStream xml = resourceStream('jacoco-high-coverage.xml')

        when:
        CoverageRatchet.CoverageCounters counters = ratchet.parse(xml)

        then:
        counters.instructionCoverage == new BigDecimal('99.00')
        counters.branchCoverage      == new BigDecimal('95.00')
    }

    void 'parse should correctly extract instruction and branch percentages from low-coverage fixture'() {
        given:
        InputStream xml = resourceStream('jacoco-low-coverage.xml')

        when:
        CoverageRatchet.CoverageCounters counters = ratchet.parse(xml)

        then:
        counters.instructionCoverage == new BigDecimal('10.00')
        counters.branchCoverage      == new BigDecimal('20.00')
    }

    void 'parse should return zero percentages when the report has no counter elements'() {
        given:
        InputStream xml = resourceStream('jacoco-zero-counters.xml')

        when:
        CoverageRatchet.CoverageCounters counters = ratchet.parse(xml)

        then:
        counters.instructionCoverage == BigDecimal.ZERO
        counters.branchCoverage      == BigDecimal.ZERO
    }

    void 'parse should throw IllegalArgumentException when the input stream is null'() {
        when:
        ratchet.parse(null)

        then:
        IllegalArgumentException ex = thrown()
        ex.message.contains('null')
    }

    void 'parse should throw IllegalArgumentException when the XML is malformed'() {
        given:
        InputStream xml = resourceStream('jacoco-malformed.xml')

        when:
        ratchet.parse(xml)

        then:
        IllegalArgumentException ex = thrown()
        ex.message.contains('Failed to parse')
    }

    // ── check() — pass cases ──────────────────────────────────────────────────

    void 'check should pass when current coverage equals baseline exactly'() {
        given:
        InputStream xml = resourceStream('jacoco-high-coverage.xml')
        Map<String, BigDecimal> baseline = [instruction: 99.00G, branch: 95.00G]

        when:
        CoverageRatchet.ComparisonResult result = ratchet.check(xml, baseline, 0.5G)

        then:
        result.passed
        result.message.contains('instruction')
        result.message.contains('branch')
    }

    void 'check should pass when current coverage is above baseline'() {
        given:
        // high-coverage fixture: instruction=99.00, branch=95.00
        // low baseline: instruction=9.0, branch=18.0
        InputStream xml = resourceStream('jacoco-high-coverage.xml')
        Map<String, BigDecimal> baseline = loadBaselineMap('baseline-low.properties')

        when:
        CoverageRatchet.ComparisonResult result = ratchet.check(xml, baseline, 0.5G)

        then:
        result.passed
        result.current['instruction'] == new BigDecimal('99.00')
        result.current['branch']      == new BigDecimal('95.00')
    }

    @Unroll
    void 'check should pass when delta is #delta% which is within the tolerance of #tolerance%'() {
        given:
        // high-coverage fixture: instruction=99.00, branch=95.00
        InputStream xml = resourceStream('jacoco-high-coverage.xml')
        Map<String, BigDecimal> baseline = [
            instruction: (99.00G + delta) as BigDecimal,
            branch:      (95.00G + delta) as BigDecimal,
        ]

        when:
        CoverageRatchet.ComparisonResult result = ratchet.check(xml, baseline, tolerance as BigDecimal)

        then:
        result.passed

        where:
        delta  | tolerance
        -0.0G  | 0.5G   // exactly at baseline
        -0.3G  | 0.5G   // below baseline but within tolerance
        -0.5G  | 0.5G   // at the tolerance boundary (not beyond it)
        -1.0G  | 1.0G   // exactly at a larger tolerance boundary
        +0.5G  | 0.5G   // above baseline
    }

    // ── check() — failure cases ───────────────────────────────────────────────

    void 'check should fail when current instruction coverage is below baseline beyond tolerance'() {
        given:
        // low-coverage fixture: instruction=10.00, branch=20.00
        // high baseline expects near 99%
        InputStream xml = resourceStream('jacoco-low-coverage.xml')
        Map<String, BigDecimal> baseline = loadBaselineMap('baseline-high.properties')

        when:
        CoverageRatchet.ComparisonResult result = ratchet.check(xml, baseline, 0.5G)

        then:
        !result.passed
        result.message.contains('regression')
        result.message.contains('instruction')
    }

    void 'check should fail when current branch coverage is below baseline beyond tolerance'() {
        given:
        // low-coverage fixture: branch=20.00
        // Baseline expects branch=94.5%
        InputStream xml = resourceStream('jacoco-low-coverage.xml')
        Map<String, BigDecimal> baseline = [instruction: 5.0G, branch: 94.5G]

        when:
        CoverageRatchet.ComparisonResult result = ratchet.check(xml, baseline, 0.5G)

        then:
        !result.passed
        result.message.contains('branch')
    }

    @Unroll
    void 'check should fail when delta is #delta% which exceeds the tolerance of #tolerance%'() {
        given:
        // high-coverage fixture: instruction=99.00, branch=95.00
        InputStream xml = resourceStream('jacoco-high-coverage.xml')
        // Set baseline so that current is delta% away
        Map<String, BigDecimal> baseline = [
            instruction: (99.00G - delta) as BigDecimal,
            branch:      new BigDecimal('0.0'),    // don't trigger a branch failure too
        ]

        when:
        CoverageRatchet.ComparisonResult result = ratchet.check(xml, baseline, tolerance as BigDecimal)

        then:
        !result.passed
        result.message.contains('instruction')

        where:
        delta  | tolerance
        1.0G   | 0.5G    // delta -1.0 with tolerance 0.5 → regression
        0.6G   | 0.5G    // delta -0.6 with tolerance 0.5 → regression
        2.0G   | 1.0G    // delta -2.0 with tolerance 1.0 → regression
    }

    void 'check should include both failing metrics in the message when both regress'() {
        given:
        // low-coverage fixture: instruction=10.00, branch=20.00
        // high baseline for both
        InputStream xml = resourceStream('jacoco-low-coverage.xml')
        Map<String, BigDecimal> baseline = [instruction: 98.5G, branch: 94.5G]

        when:
        CoverageRatchet.ComparisonResult result = ratchet.check(xml, baseline, 0.5G)

        then:
        !result.passed
        result.message.contains('instruction')
        result.message.contains('branch')
    }

    void 'check should populate the current and baseline maps on the result'() {
        given:
        InputStream xml = resourceStream('jacoco-high-coverage.xml')
        Map<String, BigDecimal> baseline = [instruction: 98.0G, branch: 94.0G]

        when:
        CoverageRatchet.ComparisonResult result = ratchet.check(xml, baseline, 0.5G)

        then:
        result.passed
        result.current['instruction'] == new BigDecimal('99.00')
        result.current['branch']      == new BigDecimal('95.00')
        result.baseline['instruction'] == new BigDecimal('98.0')
        result.baseline['branch']      == new BigDecimal('94.0')
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private InputStream resourceStream(String filename) {
        InputStream stream = getClass().getResourceAsStream(filename)
        assert stream != null : "Test fixture not found on classpath: ${filename}"
        return stream
    }

    private Map<String, BigDecimal> loadBaselineMap(String filename) {
        Properties props = new Properties()
        resourceStream(filename).withStream { InputStream s -> props.load(s) }
        return [
            instruction: new BigDecimal(props.getProperty('coverage.instruction', '0.0')),
            branch:      new BigDecimal(props.getProperty('coverage.branch',      '0.0')),
        ]
    }
}
