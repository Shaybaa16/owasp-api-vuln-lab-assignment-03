package edu.nu.owaspapivulnlab.service;

import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

@Service
public class RateLimitService {
    
    private final Map<String, RequestCounter> requestCounts = new ConcurrentHashMap<>();
    
    // SECURITY FIX: Define rate limits for different endpoints
    private static final int LOGIN_LIMIT = 5; // 5 login attempts per minute
    private static final int TRANSFER_LIMIT = 10; // 10 transfers per minute
    private static final int SEARCH_LIMIT = 20; // 20 searches per minute
    private static final int GENERAL_LIMIT = 100; // 100 general requests per minute
    
    public boolean allowRequest(String key, String endpointType) {
        long currentTime = System.currentTimeMillis();
        RequestCounter counter = requestCounts.computeIfAbsent(key, k -> new RequestCounter());
        
        // SECURITY FIX: Reset counter if more than 1 minute has passed
        if (currentTime - counter.getLastReset() > 60000) {
            counter.reset(currentTime);
        }
        
        int limit = getLimitForEndpoint(endpointType);
        return counter.incrementAndGet() <= limit;
    }
    
    private int getLimitForEndpoint(String endpointType) {
        switch (endpointType) {
            case "login": return LOGIN_LIMIT;
            case "transfer": return TRANSFER_LIMIT;
            case "search": return SEARCH_LIMIT;
            default: return GENERAL_LIMIT;
        }
    }
    
    // SECURITY FIX: Helper method to get rate limit info for clients
    public Map<String, Object> getRateLimitInfo(String key, String endpointType) {
        RequestCounter counter = requestCounts.get(key);
        int currentCount = (counter != null) ? counter.getCount() : 0;
        int limit = getLimitForEndpoint(endpointType);
        
        Map<String, Object> info = new java.util.HashMap<>();
        info.put("current", currentCount);
        info.put("limit", limit);
        info.put("remaining", Math.max(0, limit - currentCount));
        info.put("window", "1 minute");
        
        return info;
    }
    
    private static class RequestCounter {
        private final AtomicInteger count = new AtomicInteger(0);
        private long lastReset = System.currentTimeMillis();
        
        public int incrementAndGet() {
            return count.incrementAndGet();
        }
        
        public int getCount() {
            return count.get();
        }
        
        public long getLastReset() {
            return lastReset;
        }
        
        public void reset(long time) {
            count.set(0);
            lastReset = time;
        }
    }
}