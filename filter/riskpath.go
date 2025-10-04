package filter

import "strings"

func (f Filter) isRiskPath(path string) bool {
	// TODO 从数据库中获取风险列表
	if strings.Index(path, "/.well-known") == 0 {
		return true
	}
	// /wp-includes
	return f.riskPaths[path]
}

// AppendRiskPath 添加高风险路径
func (f *Filter) AppendRiskPath(paths ...string) {
	for _, path := range paths {
		f.riskPaths[path] = true
	}
}

// SetDefaultRiskPaths 设置默认高风险路径
func (f *Filter) SetDefaultRiskPaths() {
	// TODO 应该从数据库中获取
	f.riskPaths = map[string]bool{
		"/.env":       true,
		"/phpmyadmin": true,
	}
}

// DeleteRiskPath 删除高风险路径
func (f *Filter) DeleteRiskPath(paths ...string) {
	for _, path := range paths {
		delete(f.riskPaths, path)
	}
}
