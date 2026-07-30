package org.pih.warehouse.build

import java.time.LocalDate
import java.time.format.DateTimeFormatter
import java.time.format.DateTimeParseException

/**
 * Parses an OWASP dependency-check suppression XML file and identifies waiver
 * entries whose expiry dates are in the past or are missing entirely.
 *
 * <p>Each suppression's {@code <notes>} element is expected to contain a
 * structured metadata block that includes a line of the form:</p>
 * <pre>
 *   expires: yyyy-MM-dd
 * </pre>
 *
 * <p>An entry without an {@code expires:} line is treated as permanently waived
 * and is therefore reported as invalid — suppressions must never be able to
 * become permanent silently.</p>
 *
 * <p>This class intentionally has <em>no</em> dependency on the Gradle API so
 * that it can be unit-tested in plain Spock without the Gradle runtime
 * (dependency-injection / testability policy).</p>
 *
 * <p>A malformed or unparseable suppression file causes a
 * {@link RuntimeException} to be thrown rather than returning an empty list
 * — the parser never fails open.</p>
 */
class SuppressionExpiryChecker {

    private static final String EXPIRES_PREFIX = 'expires:'
    private static final DateTimeFormatter DATE_FORMAT = DateTimeFormatter.ofPattern('yyyy-MM-dd')

    /**
     * Parses the suppression XML and returns one {@link ExpiredEntry} for each
     * waiver entry that has expired or is missing a valid expiry date.
     *
     * @param xmlSource the full text content of the suppression XML file
     * @param asOf      the reference date to compare against (normally today)
     * @return list of expired or invalid suppressions; empty means all waivers are valid
     * @throws RuntimeException if the XML cannot be parsed (fail-loud, never fail-open)
     */
    List<ExpiredEntry> findExpiredEntries(String xmlSource, LocalDate asOf) {
        def root = parseXml(xmlSource)

        List<ExpiredEntry> expired = []
        root.suppress.each { suppress ->
            String identifier = resolveIdentifier(suppress)
            String notes = suppress.notes?.text()?.trim() ?: ''
            ExpiryResult result = parseExpiry(identifier, notes)

            if (!result.present) {
                expired << new ExpiredEntry(
                    identifier: identifier,
                    reason: "missing 'expires: yyyy-MM-dd' line in <notes> — " +
                            "every waiver must carry an explicit expiry date",
                    expiryDate: null
                )
            } else if (!result.date.isAfter(asOf)) {
                expired << new ExpiredEntry(
                    identifier: identifier,
                    reason: "waiver expired on ${result.date}",
                    expiryDate: result.date
                )
            }
        }
        return expired
    }

    // -------------------------------------------------------------------------
    // private helpers
    // -------------------------------------------------------------------------

    private static def parseXml(String xmlSource) {
        try {
            // Disable validation and namespace processing so the default
            // dependency-suppression namespace does not require registration.
            return new groovy.xml.XmlSlurper(false, false).parseText(xmlSource)
        } catch (Exception e) {
            throw new RuntimeException(
                "Malformed suppression file — cannot parse XML. " +
                "Failing loudly to prevent a fail-open state: ${e.message}", e)
        }
    }

    private static String resolveIdentifier(suppress) {
        if (suppress.cve.size() > 0)        return "CVE:${suppress.cve.text()}"
        if (suppress.filePath.size() > 0)   return "filePath:${suppress.filePath.text()}"
        if (suppress.gav.size() > 0)         return "GAV:${suppress.gav.text()}"
        if (suppress.packageUrl.size() > 0)  return "pkg:${suppress.packageUrl.text()}"
        return '(unknown identifier)'
    }

    private static ExpiryResult parseExpiry(String identifier, String notes) {
        for (String line : notes.readLines()) {
            String trimmed = line.trim()
            if (trimmed.startsWith(EXPIRES_PREFIX)) {
                String dateStr = trimmed.substring(EXPIRES_PREFIX.length()).trim()
                try {
                    LocalDate date = LocalDate.parse(dateStr, DATE_FORMAT)
                    return new ExpiryResult(present: true, date: date)
                } catch (DateTimeParseException e) {
                    throw new RuntimeException(
                        "Malformed expiry date '${dateStr}' for suppression '${identifier}'. " +
                        "Expected format is yyyy-MM-dd. Error: ${e.message}", e)
                }
            }
        }
        return new ExpiryResult(present: false, date: null)
    }

    // -------------------------------------------------------------------------
    // value objects
    // -------------------------------------------------------------------------

    /**
     * Describes a suppression entry that has failed the expiry check.
     */
    static class ExpiredEntry {
        /** Human-readable identifier (CVE, filePath, GAV, or pkg). */
        String identifier

        /** Human-readable explanation of why the entry failed the check. */
        String reason

        /**
         * The parsed expiry date, or {@code null} when no {@code expires:}
         * line was present in the notes.
         */
        LocalDate expiryDate

        @Override
        String toString() {
            "  • ${identifier}: ${reason}"
        }
    }

    private static class ExpiryResult {
        boolean present
        LocalDate date
    }
}
