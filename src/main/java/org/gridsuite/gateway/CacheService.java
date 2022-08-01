/**
 * Copyright (c) 2020, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package org.gridsuite.gateway;

import lombok.AllArgsConstructor;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.stereotype.Service;


/**
 * @author bendaamerahm <ahmed.bendaamer@rte-france.com>
 */
@Service
@AllArgsConstructor
public class CacheService {

    private CacheManager cacheManager;

    public void evictSingleCacheValueByKey(String cacheName, String cacheKey) {
        Cache cache = cacheManager.getCache(cacheName);
        if (cache != null) {
            cache.evict(cacheKey);
        }
    }
}
