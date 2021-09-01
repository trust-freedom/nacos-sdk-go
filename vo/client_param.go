package vo

import "github.com/nacos-group/nacos-sdk-go/common/constant"

// Nacos客户端和服务端配置
type NacosClientParam struct {
	ClientConfig  *constant.ClientConfig  // optional
	ServerConfigs []constant.ServerConfig // optional
}
