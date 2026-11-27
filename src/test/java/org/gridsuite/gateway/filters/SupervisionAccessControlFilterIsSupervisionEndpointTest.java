/**
 * Copyright (c) 2026, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.gateway.filters;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.http.server.PathContainer;

import static org.gridsuite.gateway.filters.SupervisionAccessControlFilter.isSupervisionEndpoint;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * @author Frederic Didier <frederic-f.didier at rte-france.com>
 */
class SupervisionAccessControlFilterIsSupervisionEndpointTest {

    @ParameterizedTest
    @CsvSource({
        "/v1/supervision, true",
        "/v2/supervision/, true",
        "/v10/supervision/health, true",
        "/v999/supervision/metrics, true",
        "/supervision, true",
        "/supervision/filters, true",
        "/v1/supervision;x/studies, true",
        "/supervision;x/filters, true",
        "'', false",
        "/, false",
        "/v1/studies, false",
        "/v1/studies/supervision-report, false",
        "/v1/studies/100%25, false",
        "/study/v1/supervision, false",
    })
    void testIsSupervisionEndpoint(String path, boolean expected) {
        // raw (not pre-decoded) path, as it must be given to PathContainer to avoid double
        // percent-decoding (see the filter's javadoc)
        assertEquals(expected, isSupervisionEndpoint(PathContainer.parsePath(path)));
    }
}
