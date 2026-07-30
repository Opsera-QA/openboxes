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

import groovy.json.JsonSlurper

import java.time.LocalDate
import java.time.format.DateTimeFormatter
import java.time.format.DateTimeParseException

/**
 * Framework-free (no Grails / Spring) expiry checker for the security-finding
 * allowlist at config/semgrep/allowlist.yml.
 *
 * Every entry in the allowlist must carry an {@code expiryDate} field in
 * ISO-8601 format (YYYY-MM-DD).  An entry whose expiry date is in the past
 * causes this checker to exit with a non-zero status code, failing the
 * {@code checkSecurityWaiverExpiry} Gradle task and therefore the CI build.
 *
 * The intent is to prevent the allowlist from becoming a silent suppression
 * graveyard: every suppression is time-bounded and forces a deliberate renewal
 * decision.
 *
 * Usage (via Gradle task):
 *   ./gradlew checkSecurityWaiverExpiry
 *
 * Usage (standalone):
 *   groovy SecurityWaiverExpiryChecker.groovy \
 *       config/semgrep/allowlist.yml
 *
 * Exit codes:
 *   0  All entries are valid and not expired.
 *   1  One or more entries are expired, malformed, or missing required fields.
 */
class SecurityWaiverExpiryChecker {

    static final String DATE_FORMAT = "yyyy-MM-dd"

    // Required fields that every allowlist entry must supply.
    static final List<String> REQUIRED_FIELDS = ['id', 'tool', 'owner', 'justification', 'expiryDate']

    /**
     * Check all entries in the provided allowlist YAML/JSON file.
     *
     * @param allowlistFile  The allowlist file to validate.
     * @param referenceDate  The date to compare against (defaults to today).
     * @return               A {@link CheckResult} summarising the outcome.
     */
    static CheckResult checkAllowlist(File allowlistFile, LocalDate referenceDate = LocalDate.now()) {
        if (!allowlistFile.exists()) {
            return CheckResult.error("Allowlist file not found: ${allowlistFile.absolutePath}")
        }

        List<Map> entries
        try {
            entries = parseAllowlist(allowlistFile)
        } catch (Exception e) {
            return CheckResult.error("Failed to parse allowlist file '${allowlistFile.name}': ${e.message}")
        }

        if (entries == null || entries.isEmpty()) {
            return CheckResult.ok("No entries found in ${allowlistFile.name} — nothing to check.")
        }

        List<String> violations = []

        entries.eachWithIndex { Map entry, int idx ->
            String entryLabel = entry.id ? "entry[${entry.id}]" : "entry[${idx}]"

            // Verify required fields are present and non-blank.
            REQUIRED_FIELDS.each { String field ->
                if (!entry.containsKey(field) || !entry[field]?.toString()?.trim()) {
                    violations << "${entryLabel}: missing required field '${field}'"
                }
            }

            // Validate and check the expiry date.
            if (entry.expiryDate) {
                LocalDate expiry
                try {
                    expiry = LocalDate.parse(entry.expiryDate.toString().trim(), DateTimeFormatter.ofPattern(DATE_FORMAT))
                } catch (DateTimeParseException e) {
                    violations << "${entryLabel}: invalid expiryDate '${entry.expiryDate}' — expected ${DATE_FORMAT} format"
                    return  // continue to next entry
                }

                if (!expiry.isAfter(referenceDate)) {
                    violations << "${entryLabel}: EXPIRED on ${entry.expiryDate} " +
                            "(owner: ${entry.owner ?: 'unknown'}, " +
                            "file: ${entry.file ?: 'unknown'}, " +
                            "story: ${entry.remediationStory ?: 'none'}). " +
                            "Either remediate the finding or extend the expiry with team approval."
                }
            }
        }

        if (violations) {
            return CheckResult.violations(violations, entries.size())
        }
        return CheckResult.ok("All ${entries.size()} allowlist entr${entries.size() == 1 ? 'y' : 'ies'} in '${allowlistFile.name}' are valid and not expired.")
    }

    /**
     * Parse an allowlist file.  Supports:
     *   - YAML files (simple key: value and list-of-maps format)
     *   - JSON files
     *
     * The YAML parser is hand-rolled to avoid requiring an external YAML library
     * dependency in this framework-free utility.  It handles the specific subset
     * of YAML used in config/semgrep/allowlist.yml (block sequences of mappings).
     */
    static List<Map> parseAllowlist(File file) {
        String content = file.text
        String filename = file.name.toLowerCase()

        if (filename.endsWith('.json')) {
            def parsed = new JsonSlurper().parseText(content)
            if (parsed instanceof List) {
                return parsed as List<Map>
            }
            if (parsed instanceof Map && parsed.entries instanceof List) {
                return parsed.entries as List<Map>
            }
            throw new IllegalArgumentException("Expected JSON array or object with 'entries' array")
        }

        // Simple YAML block-sequence parser for files structured as:
        //   entries:
        //     - id: "..."
        //       field: "..."
        return parseSimpleYamlEntries(content)
    }

    /**
     * Parse a YAML file that contains an {@code entries:} block of simple
     * key-value mappings.  Handles quoted and unquoted scalar values and
     * multi-line block scalar (>) values.
     *
     * This is intentionally minimal — it is NOT a full YAML parser.  It handles
     * exactly the schema used by config/semgrep/allowlist.yml.
     */
    static List<Map> parseSimpleYamlEntries(String yaml) {
        List<Map> entries = []
        Map<String, Object> currentEntry = null
        String currentKey = null
        StringBuilder blockScalar = null
        boolean inEntriesSection = false

        yaml.eachLine { String rawLine ->
            String line = rawLine

            // Detect start of the entries: block
            if (line.trim() == 'entries:') {
                inEntriesSection = true
                return
            }
            if (!inEntriesSection) return

            // Skip pure comment lines
            if (line.trim().startsWith('#')) {
                return
            }

            // Count leading spaces for indentation depth
            int indent = line.length() - line.stripLeading().length()

            // New list entry (starts with '  - ')
            if (line =~ /^\s{2}-\s+.*/) {
                // Flush previous block scalar
                if (blockScalar != null && currentEntry != null && currentKey != null) {
                    currentEntry[currentKey] = blockScalar.toString().trim()
                    blockScalar = null
                    currentKey = null
                }
                // Save current entry
                if (currentEntry != null) entries << currentEntry
                currentEntry = [:]
                // Parse the first key-value on the same line as the dash
                String rest = line.replaceFirst(/^\s*-\s+/, '')
                parseKeyValue(rest, currentEntry)
                return
            }

            // Continuation of a block scalar (>)
            if (blockScalar != null && indent >= 6) {
                blockScalar.append(line.trim()).append(' ')
                return
            } else if (blockScalar != null) {
                // Indentation dropped — block scalar ended
                if (currentEntry != null && currentKey != null) {
                    currentEntry[currentKey] = blockScalar.toString().trim()
                }
                blockScalar = null
                currentKey = null
            }

            // Regular key: value lines inside an entry (indent >= 4)
            if (currentEntry != null && indent >= 4 && line.contains(':')) {
                String trimmed = line.trim()
                int colonIdx = trimmed.indexOf(':')
                String key = trimmed.substring(0, colonIdx).trim()
                String value = trimmed.substring(colonIdx + 1).trim()

                if (value == '>') {
                    // Start of a block scalar
                    currentKey = key
                    blockScalar = new StringBuilder()
                } else if (value) {
                    // Strip surrounding quotes
                    value = value.replaceAll(/^["']|["']$/, '')
                    currentEntry[key] = value
                }
            }
        }

        // Flush last block scalar and entry
        if (blockScalar != null && currentEntry != null && currentKey != null) {
            currentEntry[currentKey] = blockScalar.toString().trim()
        }
        if (currentEntry != null) entries << currentEntry

        return entries
    }

    private static void parseKeyValue(String text, Map entry) {
        if (!text?.contains(':')) return
        int colonIdx = text.indexOf(':')
        String key = text.substring(0, colonIdx).trim()
        String value = text.substring(colonIdx + 1).trim()
        value = value.replaceAll(/^["']|["']$/, '')
        if (key && value) entry[key] = value
    }

    /**
     * Command-line entry point.
     *
     * Accepts one or more allowlist file paths as arguments.
     * Exits with code 1 if any file has violations; 0 otherwise.
     */
    static void main(String[] args) {
        if (!args) {
            System.err.println("Usage: SecurityWaiverExpiryChecker <allowlist-file> [<allowlist-file2> ...]")
            System.exit(1)
        }

        boolean anyViolation = false
        args.each { String path ->
            File f = new File(path)
            CheckResult result = checkAllowlist(f)
            if (result.ok) {
                println "[PASS] ${result.message}"
            } else {
                System.err.println("[FAIL] ${result.message}")
                result.violations.each { v -> System.err.println("  - ${v}") }
                anyViolation = true
            }
        }

        System.exit(anyViolation ? 1 : 0)
    }

    // ── Inner result type ────────────────────────────────────────────────────

    static class CheckResult {
        final boolean ok
        final String message
        final List<String> violations
        final int totalEntries

        private CheckResult(boolean ok, String message, List<String> violations, int totalEntries) {
            this.ok = ok
            this.message = message
            this.violations = violations ?: []
            this.totalEntries = totalEntries
        }

        static CheckResult ok(String message) {
            new CheckResult(true, message, [], 0)
        }

        static CheckResult error(String message) {
            new CheckResult(false, message, [message], 0)
        }

        static CheckResult violations(List<String> violations, int totalEntries) {
            String summary = "${violations.size()} violation(s) found in ${totalEntries} entr${totalEntries == 1 ? 'y' : 'ies'}:"
            new CheckResult(false, summary, violations, totalEntries)
        }
    }
}
