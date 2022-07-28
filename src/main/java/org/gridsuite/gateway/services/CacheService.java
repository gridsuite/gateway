package org.gridsuite.gateway.services;

import lombok.AllArgsConstructor;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

@Service
@AllArgsConstructor
public class CacheService {

    CacheManager cacheManager;

    public void evictSingleCacheValue(String cacheName, String cacheKey) {
        Cache cache = cacheManager.getCache(cacheName);
        if (cache != null) {
            cache.evict(cacheKey);
        }
    }

    public void evictAllCacheValuesByName(String cacheName) {
        Cache cache = cacheManager.getCache(cacheName);
        if(cacheManager.getCache(cacheName) != null) {
            cache.clear();
        }
    }

    public void evictAllCaches() {
        cacheManager.getCacheNames().stream()
                .forEach(cacheName -> cacheManager.getCache(cacheName).clear());
    }

    @Scheduled(fixedRate = 300000)
    public void evictAllcachesAtIntervals() {
        evictAllCaches();
    }
}
