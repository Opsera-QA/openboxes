/**
 * Copyright (c) 2022 Partners In Health.  All rights reserved.
 * The use and distribution terms for this software are covered by the
 * Eclipse Public License 1.0 (http://opensource.org/licenses/eclipse-1.0.php)
 * which can be found in the file epl-v10.html at the root of this distribution.
 * By using this software in any fashion, you are agreeing to be bound by
 * the terms of this license.
 * You must not remove this notice, or any other, from this software.
 */
package org.pih.warehouse.build

import groovy.util.XmlParser

/**
 * Framework-free ratchet that parses a JaCoCo aggregate XML report and compares
 * instruction and branch coverage percentages against a committed baseline.
 *
 * This class has no dependency on Gradle types so that it can be unit-tested
 * with plain Spock specs without a full build-script environment.  The Gradle
 * {@code coverageRatchet} task in {@code gradle/coverage.gradle} is a thin
 * adapter that wires this class into the build lifecycle.
 *
 * <h3>Usage</h3>
 * <pre>
 * CoverageRatchet ratchet = new CoverageRatchet()
 * CoverageCounters counters = ratchet.parse(xmlInputStream)
 * ComparisonResult result   = ratchet.check(xmlInputStream, baselineMap, tolerance)
 * </pre>
 */
class CoverageRatchet {

    // ── Value objects ─────────────────────────────────────────────────────────

    /**
     * Raw parsed coverage percentages extracted from a JaCoCo XML report.
     * Both values are in the range [0, 100] with two decimal places.
     */
    static class CoverageCounters {
        /** Instruction coverage as a percentage, e.g. {@code 74.53}. */
        BigDecimal instructionCoverage = BigDecimal.ZERO

        /** Branch coverage as a percentage, e.g. {@code 61.20}. */
        BigDecimal branchCoverage = BigDecimal.ZERO
    }

    /**
     * The outcome of comparing current coverage against a baseline.
     */
    static class ComparisonResult {
        /**
         * {@code true} when all metrics are at or above {@code baseline - tolerance};
         * {@code false} when at least one metric has regressed.
         */
        boolean passed

        /** Human-readable summary describing the outcome. */
        String message

        /** Current coverage values keyed by lower-case metric name. */
        Map<String, BigDecimal> current

        /** Baseline values that were compared against. */
        Map<String, BigDecimal> baseline
    }

    // ── Public API ────────────────────────────────────────────────────────────

    /**
     * Parses a JaCoCo aggregate XML report and returns the top-level instruction
     * and branch coverage percentages.
     *
     * <p>DTD validation is disabled because the {@code report.dtd} referenced by
     * JaCoCo's DOCTYPE declaration is not available on the application classpath.</p>
     *
     * @param jacocoXml an open {@code InputStream} of valid JaCoCo XML (not null)
     * @return parsed coverage counters (never null)
     * @throws IllegalArgumentException if {@code jacocoXml} is null or cannot be parsed
     */
    CoverageCounters parse(InputStream jacocoXml) {
        if (jacocoXml == null) {
            throw new IllegalArgumentException(
                "JaCoCo XML input stream must not be null"
            )
        }

        def report
        try {
            XmlParser parser = new XmlParser(false, false)
            // Disable DOCTYPE declaration enforcement and external DTD loading so
            // the report can be parsed without network access or a local DTD file.
            parser.setFeature('http://apache.org/xml/features/disallow-doctype-decl', false)
            parser.setFeature('http://apache.org/xml/features/nonvalidating/load-external-dtd', false)
            report = parser.parse(jacocoXml)
        } catch (Exception e) {
            throw new IllegalArgumentException(
                "Failed to parse JaCoCo XML: ${e.message}", e
            )
        }

        return new CoverageCounters(
            instructionCoverage: extractPercentage(report, 'INSTRUCTION'),
            branchCoverage:      extractPercentage(report, 'BRANCH'),
        )
    }

    /**
     * Parses a JaCoCo XML report and compares the resulting coverage against
     * {@code baseline} within the given {@code tolerance}.
     *
     * @param jacocoXml  an open {@code InputStream} of JaCoCo XML
     * @param baseline   map from lower-case metric name
     *                   ({@code "instruction"}, {@code "branch"}) to baseline %
     * @param tolerance  maximum acceptable negative delta before a failure is declared
     * @return a {@link ComparisonResult} describing the outcome
     * @throws IllegalArgumentException if the XML cannot be parsed
     */
    ComparisonResult check(InputStream jacocoXml,
                           Map<String, BigDecimal> baseline,
                           BigDecimal tolerance) {
        CoverageCounters counters = parse(jacocoXml)

        Map<String, BigDecimal> current = [
            instruction: counters.instructionCoverage,
            branch:      counters.branchCoverage,
        ]

        List<String> failures = []
        baseline.each { String metric, BigDecimal baselineValue ->
            BigDecimal currentValue = current.getOrDefault(metric, BigDecimal.ZERO)
            BigDecimal delta = currentValue - baselineValue
            if (delta < -tolerance) {
                failures << String.format(
                    "%s: baseline=%.2f%%, current=%.2f%%, delta=%+.2f%% (tolerance=%.2f%%)",
                    metric, baselineValue, currentValue, delta, tolerance
                )
            }
        }

        if (failures) {
            return new ComparisonResult(
                passed:   false,
                message:  "Coverage regression detected:\n  " + failures.join('\n  '),
                current:  current,
                baseline: baseline,
            )
        }

        String summary = current.collect { metric, value ->
            String.format("%s=%.2f%% (baseline: %.2f%%)", metric, value,
                baseline.getOrDefault(metric, BigDecimal.ZERO))
        }.join(', ')

        return new ComparisonResult(
            passed:   true,
            message:  summary,
            current:  current,
            baseline: baseline,
        )
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    private BigDecimal extractPercentage(def report, String counterType) {
        def counter = report.counter.find { it.@type == counterType }
        if (counter == null) {
            return BigDecimal.ZERO
        }

        long missed  = (counter.@missed  ?: '0').toLong()
        long covered = (counter.@covered ?: '0').toLong()
        long total   = missed + covered

        if (total == 0L) {
            return BigDecimal.ZERO
        }

        return (covered * 100.0G / total).setScale(2, BigDecimal.ROUND_HALF_UP)
    }
}
