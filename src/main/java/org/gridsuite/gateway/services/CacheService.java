package org.gridsuite.gateway.services;

import lombok.AllArgsConstructor;
import org.springframework.cache.CacheManager;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

@Service
@AllArgsConstructor
public class CacheService {

    CacheManager cacheManager;

    public void evictSingleCacheValue(String cacheName, String cacheKey) {
        cacheManager.getCache(cacheName).evict(cacheKey);
    }

    public void evictAllCacheValuesByName(String cacheName) {
        cacheManager.getCache(cacheName).clear();
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
