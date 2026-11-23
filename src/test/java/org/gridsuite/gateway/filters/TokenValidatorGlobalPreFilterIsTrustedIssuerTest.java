/**
 * Copyright (c) 2026, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.gateway.filters;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static org.gridsuite.gateway.filters.TokenValidatorGlobalPreFilter.isTrustedIssuer;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TokenValidatorGlobalPreFilterIsTrustedIssuerTest {

    @ParameterizedTest
    @CsvSource({
        "https://other.org",
        "https://other.com",
        "http://other.org",
        "https://other.org:50000",
        "https://sub.other.org",
        "https://other.org/",
        "https://other.org/tenantid/iss",
        "https://otherlonger.org",
    })
    void testRejectsBasic(String issuer) {
        assertFalse(isTrustedIssuer(issuer, "https://identity.org"));
    }

    @Test
    void testBasicAtPath() {
        assertTrue(isTrustedIssuer("https://identity.org/tenantidA/iss", "https://identity.org/tenantidA/iss"));
        assertFalse(isTrustedIssuer("https://identity.org/tenantidB/iss", "https://identity.org/tenantidA/iss"));
        assertTrue(isTrustedIssuer("https://identity.org/tenantidA/iss/nested", "https://identity.org/tenantidA/iss")); // we don't use it today yet...
    }

    private static Stream<String> acceptedSuffixAfterAuthority() {
        return Stream.of(
            "https://identity.org/",
            "https://identity.org/tenantid/iss"
        );
    }

    private static Stream<String> rejectedSuffixAfterAuthorityBoundary() {
        return Stream.of(
            "https://identity.organic",
            "https://identity.org.other.com",
            "https://identity.org:50000",
            "https://identity.org@other.com"
        );
    }

    @ParameterizedTest
    @MethodSource("acceptedSuffixAfterAuthority")
    @CsvSource("https://identity.org")
    void testAcceptsIssuerWhenReferenceWithoutTrailingSlash(String issuer) {
        assertTrue(isTrustedIssuer(issuer, "https://identity.org"));
    }

    @ParameterizedTest
    @MethodSource("acceptedSuffixAfterAuthority")
    void testAcceptsIssuerWhenReferenceWithTrailingSlash(String issuer) {
        assertTrue(isTrustedIssuer(issuer, "https://identity.org/"));
    }

    @ParameterizedTest
    @MethodSource("rejectedSuffixAfterAuthorityBoundary")
    void testRejectsIssuerWhenReferenceWithoutTrailingSlash(String issuer) {
        assertFalse(isTrustedIssuer(issuer, "https://identity.org"));
    }

    @ParameterizedTest
    @MethodSource("rejectedSuffixAfterAuthorityBoundary")
    void testRejectsIssuerWhenReferenceWithTrailingSlash(String issuer) {
        assertFalse(isTrustedIssuer(issuer, "https://identity.org/"));
    }

    private static Stream<String> rejectedSuffixAfterPortBoundary() {
        return Stream.of(
            "https://identity.org:4430"
        );
    }

    private static Stream<String> acceptedSuffixAfterPort() {
        return Stream.of(
            "https://identity.org:443/",
            "https://identity.org:443/tenantid/iss"
        );
    }

    @ParameterizedTest
    @MethodSource("rejectedSuffixAfterPortBoundary")
    void testRejectsIssuerWhenReferenceWithPortWithoutTrailingSlash(String issuer) {
        assertFalse(isTrustedIssuer(issuer, "https://identity.org:443"));
    }

    @ParameterizedTest
    @MethodSource("rejectedSuffixAfterPortBoundary")
    void testRejectsIssuerWhenReferenceWithPortWithTrailingSlash(String issuer) {
        assertFalse(isTrustedIssuer(issuer, "https://identity.org:443/"));
    }

    @ParameterizedTest
    @MethodSource("acceptedSuffixAfterPort")
    @CsvSource("https://identity.org:443")
    void testAcceptsIssuerWhenReferenceWithPortWithoutTrailingSlash(String issuer) {
        assertTrue(isTrustedIssuer(issuer, "https://identity.org:443"));
    }

    @ParameterizedTest
    @MethodSource("acceptedSuffixAfterPort")
    void testAcceptsIssuerWhenReferenceWithPortWithTrailingSlash(String issuer) {
        assertTrue(isTrustedIssuer(issuer, "https://identity.org:443/"));
    }

    @Test
    // Arguably bad configuration should be detected at startup but it helps
    // to know that the behavior of the function is not too bad under bad conf
    void testReferenceBadConfiguration() {
        // Not needed because it's bad configuration but this is the current behavior. Not a problem
        // because you can't do anything with an empty issuer anyway (e.g. can't download public keys)
        assertTrue(isTrustedIssuer("", ""));

        // Specific exception types not really needed (or even throwing at all actually, rejecting
        // would be acceptable), but testing for exceptions explicitly avoids having the test pass
        // (that is, an exception is thrown in test) but for an exception tied to the test setup or
        // execution, with production executions behaving differently and not throwing (and in the
        // worst case, accepting the input)
        assertThrows(StringIndexOutOfBoundsException.class,
            () -> isTrustedIssuer("/", ""));
        assertThrows(StringIndexOutOfBoundsException.class,
            () -> isTrustedIssuer("https://other.org", ""));
        assertThrows(NullPointerException.class,
            () -> isTrustedIssuer("https://other.org", null));
    }

    @Test
    void testAcceptsAlternateProtocol() {
        assertTrue(isTrustedIssuer("http://identity.org", "http://identity.org")); // used in dev
    }

    @Test
    void testAcceptsIPv4() {
        assertTrue(isTrustedIssuer("https://1.2.3.4", "https://1.2.3.4"));
        assertTrue(isTrustedIssuer("http://1.2.3.4:4321", "http://1.2.3.4:4321")); // used in dev
    }

    @Test
    void testAcceptsIPv6() {
        // we don't use it today yet...
        assertTrue(isTrustedIssuer("https://[2001:db8::1]", "https://[2001:db8::1]"));
        assertTrue(isTrustedIssuer("http://[2001:db8::1]:1234", "http://[2001:db8::1]:1234"));
    }

    @Test
    void testAcceptsExactSubdomain() {
        assertTrue(isTrustedIssuer("https://sub.identity.org", "https://sub.identity.org")); // we don't use it today yet...
    }

    // We never accept based on supposed equivalence or other potential relation (except for http path tested separately)
    @ParameterizedTest
    @CsvSource({
        // default implicit port vs explicit value (both ways)
        "https://identity.org, https://identity.org:443",
        "https://identity.org:443, https://identity.org",
        // subdomains (both ways)
        "https://sub.identity.org, https://identity.org",
        "https://identity.org, https://sub.identity.org",
        // dns search path (one way: never in conf)
        "https://identity, https://identity.internal.search.path",
        // protocol (both ways)
        "http://identity.org, https://identity.org",
        "https://identity.org, http://identity.org",
        // missing protocol (one way: never in conf)
        "identity.org, https://identity.org",
        // userinfo (one way: never in conf)
        "https://user:pass@identity.org, https://identity.org",
        // query (one way: never in conf)
        "https://identity.org?foo=bar, https://identity.org",
        // fragment (one way: never in conf)
        "https://identity.org#foo, https://identity.org"
    })
    void testRejectedIssuerVariations(String issuer, String ref) {
        assertFalse(isTrustedIssuer(issuer, ref));
    }

    // currently we accept these variations, but it is not needed, just recording the behavior
    @ParameterizedTest
    @CsvSource({
        // query (one way: never in conf)
        "https://identity.org/?foo=bar, https://identity.org",
        "https://identity.org/tenantid?foo=bar, https://identity.org",
        // fragment (one way: never in conf)
        "https://identity.org/#foo, https://identity.org",
        "https://identity.org/tenantid#foo, https://identity.org",
        // path dot segment
        // note: to change we would need a changed implementation to look and maybe parse
        // arbitrarily big input, not just configured reference.
        "https://identity.org/tenantidA/./, https://identity.org/tenantidA/",
        "https://identity.org/tenantidA/../tenantidB, https://identity.org/tenantidA/" // this one is potentially not good...
    })
    void testAcceptedIssuerVariations(String issuer, String ref) {
        assertTrue(isTrustedIssuer(issuer, ref));
    }
}
