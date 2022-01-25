/*
  Copyright (c) 2021, RTE (http://www.rte-france.com)
  This Source Code Form is subject to the terms of the Mozilla Public
  License, v. 2.0. If a copy of the MPL was not distributed with this
  file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.gateway.dto;

import lombok.*;

import java.util.List;
import java.util.UUID;

/**
 * @author Slimane Amar <slimane.amar at rte-france.com>
 */
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@Getter
@Setter
public class AccessControlInfos {

    private List<UUID> elementUuids;

    public static AccessControlInfos create(@NonNull List<UUID> uuids) {
        if (uuids.isEmpty()) {
            throw new IllegalArgumentException("List of elements is empty");
        }
        return new AccessControlInfos(uuids);
    }
}
