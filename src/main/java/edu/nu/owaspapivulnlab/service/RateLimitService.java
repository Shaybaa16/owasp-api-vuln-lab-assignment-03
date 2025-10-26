package edu.nu.owaspapivulnlab.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

@Service
public class RateLimitService {

    private final Map<String, RequestCounter> requestCounts = new ConcurrentHashMap<>();

    // ✅ Toggle rate limiting globally via config
    @Value("${rate.limit.enabled:true}")
    private boolean rateLimitEnabled;

    private final Environment env;

    // ✅ Inject environment to detect active profile (e.g., “test”)
    public RateLimitService(Environment env) {
        this.env = env;
    }

    // ✅ Main limiter
    public boolean allowRequest(String key, String endpointType) {
        String[] profiles = env.getActiveProfiles();
        for (String p : profiles) {
            if ("test".equalsIgnoreCase(p)) {
                return true; // skip limits entirely during other tests
            }
        }

        if (!rateLimitEnabled && !"login".equalsIgnoreCase(endpointType)) {
            return true;
        }

        long currentTime = System.currentTimeMillis();
        RequestCounter counter = requestCounts.computeIfAbsent(key, k -> new RequestCounter());

        if (currentTime - counter.getLastReset() > 60000) {
            counter.reset(currentTime);
        }

        int limit = getLimitForEndpoint(endpointType);

        // ✅ Corrected: allow up to 5th request, block from 6th
        return counter.incrementAndGet() <= limit;
    }


    // ✅ Define per-endpoint limits
    private int getLimitForEndpoint(String endpointType) {
        switch (endpointType.toLowerCase()) {
            case "login": return 5;      // 5 login attempts/min
            case "transfer": return 10;  // 10 transfers/min
            case "search": return 20;    // 20 searches/min
            default: return 100;         // general requests
        }
    }

    // ✅ Optional helper: expose limit info (for debugging)
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

    // ✅ Optional: clear all counters (useful in integration tests)
    public void clear() {
        requestCounts.clear();
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
