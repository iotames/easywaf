package filter

import (
	"fmt"
)

// 拦截类型常量
const (
	BLOCK_TYPE_BLACK_IP = iota
	BLOCK_TYPE_USER_AGENT
	BLOCK_TYPE_RATE_LIMIT
	BLOCK_TYPE_RISK_PATH
	BLOCK_TYPE_BODY_SIZE
	BLOCK_TYPE_METHOD
	BLOCK_TYPE_PATH_INJECTION
	BLOCK_TYPE_SQL_INJECTION
	BLOCK_TYPE_XSS
)

// 错误类型映射
var errorMessages = map[int]string{
	BLOCK_TYPE_BLACK_IP:       "IP地址被列入黑名单",
	BLOCK_TYPE_USER_AGENT:     "可疑的用户代理",
	BLOCK_TYPE_RATE_LIMIT:     "请求频率过高",
	BLOCK_TYPE_RISK_PATH:      "访问可疑路径",
	BLOCK_TYPE_BODY_SIZE:      "请求体超出限制",
	BLOCK_TYPE_METHOD:         "请求方法被禁止",
	BLOCK_TYPE_PATH_INJECTION: "检测到路径注入攻击",
	BLOCK_TYPE_SQL_INJECTION:  "检测到SQL注入尝试",
	BLOCK_TYPE_XSS:            "检测到XSS攻击尝试",
}

// 自定义错误类型
type ErrorBlock struct {
	Type    int    // 错误类型
	Message string // 错误信息
	IP      string // 客户端IP

}

func (b ErrorBlock) Error() string {
	return fmt.Sprintf("request blocked: Type=%d, Message=%s, IP=%s", b.Type, b.Message, b.IP)
}

// 创建拦截错误
func NewErrorBlock(errorType int, ip string) *ErrorBlock {
	errmsg, ok := errorMessages[errorType]
	if !ok {
		errmsg = "未知"
	}
	return &ErrorBlock{
		Type:    errorType,
		Message: errmsg,
		IP:      ip,
	}
}
