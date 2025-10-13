package filter

import (
	"regexp"
)

type UserAgentLimiter struct {
	suspiciousUA []*regexp.Regexp
}

func NewUserAgentLimiter() *UserAgentLimiter {
	return &UserAgentLimiter{
		suspiciousUA: compileSuspiciousPatterns(),
	}
}

func (u UserAgentLimiter) Allow(ua string) bool {
	for _, pattern := range u.suspiciousUA {
		if pattern.MatchString(ua) {
			return false
		}
	}
	return true
}

func (u UserAgentLimiter) IsSpider(ua string) bool {
	re, _ := regexp.Compile(`(?i)(bot|scrapy|crawler|spider|scanner|baiduspider|sogou|yandex|duckduckbot|slurp|bingbot)`)
	return re.MatchString(ua)
}

// compileSuspiciousPatterns 编译可疑用户代理模式
func compileSuspiciousPatterns() []*regexp.Regexp {
	patterns := []string{
		`(?i)(bot|scrapy|crawler|spider|scanner|baiduspider|sogou|yandex|duckduckbot|slurp|bingbot)`,
		`(?i)(sqlmap|nmap|metasploit|nikto|acunetix|nessus)`,
		`(?i)(curl|wget|python|java|requests|ruby|perl|httpclient|libwww-perl|okhttp|go-http-client|phantomjs|headless|fetch|axios|http_request2|http_request|http_get|http_post)`,
	}
	// 正则匹配去掉php，一加手机：OnePlus Ace 2 (PHP110)。典型UserAgent: Mozilla/5.0 (Linux; U; Android 15; zh-cn; PHP110 Build/AP3A.240617.008) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/115.0.5790.168 Mobile Safari/537.36 HeyTapBrowser/40.10.2.1
	var regexps []*regexp.Regexp
	for _, pattern := range patterns {
		if re, err := regexp.Compile(pattern); err == nil {
			regexps = append(regexps, re)
		}
	}
	return regexps
}
