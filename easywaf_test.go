package easywaf

import (
	"testing"

	"github.com/iotames/easywaf/filter"
)

func TestUserAgentLimiter(t *testing.T) {
	bakualist := []string{
		// 可疑UA
		"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; ClaudeBot/1.0; +claudebot@anthropic.c",
		"Googlebot/2.1 (+http://www.google.com/bot.html)",
		"sqlmap/1.3.9#stable (http://sqlmap.org)",
		"SomeBotttttt",
		"OtherBBOTTtt",
		"Scrapy/1.1.2 (+http://scrapy.org)",
		"curl/7.68.0",
		"python-requests/2.25.1",
		"nmap/7.91",
		"Java/1.8.0_181",
		"Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
	}
	okualist := []string{
		// 正常UA
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 13_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1.1 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15",
	}

	limiter := filter.NewUserAgentLimiter()
	for _, ua := range bakualist {
		allowed := limiter.Allow(ua)
		if allowed {
			t.Errorf("UserAgent %q should be blocked, but was allowed", ua)
		}
	}
	for _, ua := range okualist {
		allowed := limiter.Allow(ua)
		if !allowed {
			t.Errorf("UserAgent %q should be allowed, but was blocked", ua)
		}
	}
}
