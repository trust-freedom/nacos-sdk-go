/*
 * Copyright 1999-2020 Alibaba Group Holding Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package config_client

import (
	"errors"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aliyun/alibaba-cloud-sdk-go/services/kms"
	"github.com/nacos-group/nacos-sdk-go/clients/cache"
	"github.com/nacos-group/nacos-sdk-go/clients/nacos_client"
	"github.com/nacos-group/nacos-sdk-go/common/constant"
	"github.com/nacos-group/nacos-sdk-go/common/http_agent"
	"github.com/nacos-group/nacos-sdk-go/common/logger"
	"github.com/nacos-group/nacos-sdk-go/common/nacos_error"
	"github.com/nacos-group/nacos-sdk-go/model"
	"github.com/nacos-group/nacos-sdk-go/util"
	"github.com/nacos-group/nacos-sdk-go/vo"
)

// ConfigClient包含NacosClient，还有些配置中心相关的属性，如本地缓存相关，真正的配置中心操作是交给ConfigProxy
// 实现IConfigClient接口
type ConfigClient struct {
	nacos_client.INacosClient
	kmsClient        *kms.Client
	localConfigs     []vo.ConfigParam
	mutex            sync.Mutex
	configProxy      ConfigProxy
	configCacheDir   string
	currentTaskCount int  // 当前长轮训任务数量，每3000个监听一个任务
	cacheMap         cache.ConcurrentMap // 存放监听相关的缓存，key为 dataId + "@@" + group + "@@" + namespaceId
	                                     // listenerSize = cacheMap.Count
	schedulerMap     cache.ConcurrentMap // 存放定时执行的长轮训任务，key为taskId，value为boolean类型，代表当前任务是否继续执行
}

const (
	perTaskConfigSize = 3000
	executorErrDelay  = 5 * time.Second
)

type cacheData struct {
	isInitializing    bool
	dataId            string
	group             string
	content           string
	tenant            string
	cacheDataListener *cacheDataListener
	md5               string
	appName           string
	taskId            int
}

type cacheDataListener struct {
	listener vo.Listener
	lastMd5  string
}

func NewConfigClient(nc nacos_client.INacosClient) (*ConfigClient, error) {
	config := &ConfigClient{
		cacheMap:     cache.NewConcurrentMap(),
		schedulerMap: cache.NewConcurrentMap(),
	}
	// schedulerMap放入root任务，value=true表示执行
	config.schedulerMap.Set("root", true)
	// 开启root任务，执行func为config.listenConfigExecutor()
	go config.delayScheduler(time.NewTimer(1*time.Millisecond), 10*time.Millisecond, "root", config.listenConfigExecutor())

	config.INacosClient = nc
	clientConfig, err := nc.GetClientConfig()
	if err != nil {
		return config, err
	}
	serverConfig, err := nc.GetServerConfig()
	if err != nil {
		return config, err
	}
	httpAgent, err := nc.GetHttpAgent()
	if err != nil {
		return config, err
	}
	err = logger.InitLogger(logger.Config{
		Level:        clientConfig.LogLevel,
		OutputPath:   clientConfig.LogDir,
		RotationTime: clientConfig.RotateTime,
		MaxAge:       clientConfig.MaxAge,
	})
	if err != nil {
		return config, err
	}
	config.configCacheDir = clientConfig.CacheDir + string(os.PathSeparator) + "config"
	config.configProxy, err = NewConfigProxy(serverConfig, clientConfig, httpAgent)
	if clientConfig.OpenKMS {
		kmsClient, err := kms.NewClientWithAccessKey(clientConfig.RegionId, clientConfig.AccessKey, clientConfig.SecretKey)
		if err != nil {
			return config, err
		}
		config.kmsClient = kmsClient
	}
	return config, err
}

func (client *ConfigClient) sync() (clientConfig constant.ClientConfig,
	serverConfigs []constant.ServerConfig, agent http_agent.IHttpAgent, err error) {
	clientConfig, err = client.GetClientConfig()
	if err != nil {
		logger.Errorf("getClientConfig catch error:%+v", err)
		return
	}
	serverConfigs, err = client.GetServerConfig()
	if err != nil {
		logger.Errorf("getServerConfig catch error:%+v", err)
		return
	}

	agent, err = client.GetHttpAgent()
	if err != nil {
		logger.Errorf("getHttpAgent catch error:%+v", err)
	}
	return
}

// 获取指定group、dataId的配置信息
func (client *ConfigClient) GetConfig(param vo.ConfigParam) (content string, err error) {
	content, err = client.getConfigInner(param)

	if err != nil {
		return "", err
	}

	return client.decrypt(param.DataId, content)
}

func (client *ConfigClient) decrypt(dataId, content string) (string, error) {
	if client.kmsClient != nil && strings.HasPrefix(dataId, "cipher-") {
		request := kms.CreateDecryptRequest()
		request.Method = "POST"
		request.Scheme = "https"
		request.AcceptFormat = "json"
		request.CiphertextBlob = content
		response, err := client.kmsClient.Decrypt(request)
		if err != nil {
			return "", fmt.Errorf("kms decrypt failed: %v", err)
		}
		content = response.Plaintext
	}
	return content, nil
}

func (client *ConfigClient) encrypt(dataId, content string) (string, error) {
	if client.kmsClient != nil && strings.HasPrefix(dataId, "cipher-") {
		request := kms.CreateEncryptRequest()
		request.Method = "POST"
		request.Scheme = "https"
		request.AcceptFormat = "json"
		request.KeyId = "alias/acs/acm" // use default key
		request.Plaintext = content
		response, err := client.kmsClient.Encrypt(request)
		if err != nil {
			return "", fmt.Errorf("kms encrypt failed: %v", err)
		}
		content = response.CiphertextBlob
	}
	return content, nil
}

func (client *ConfigClient) getConfigInner(param vo.ConfigParam) (content string, err error) {
	if len(param.DataId) <= 0 {
		err = errors.New("[client.GetConfig] param.dataId can not be empty")
		return "", err
	}
	if len(param.Group) <= 0 {
		err = errors.New("[client.GetConfig] param.group can not be empty")
		return "", err
	}
	clientConfig, _ := client.GetClientConfig()
	cacheKey := util.GetConfigCacheKey(param.DataId, param.Group, clientConfig.NamespaceId)
	content, err = client.configProxy.GetConfigProxy(param, clientConfig.NamespaceId, clientConfig.AccessKey, clientConfig.SecretKey)

	if err != nil {
		logger.Infof("get config from server error:%+v ", err)
		if _, ok := err.(*nacos_error.NacosError); ok {
			nacosErr := err.(*nacos_error.NacosError)
			if nacosErr.ErrorCode() == "404" {
				cache.WriteConfigToFile(cacheKey, client.configCacheDir, "")
				logger.Warnf("[client.GetConfig] config not found, dataId: %s, group: %s, namespaceId: %s.", param.DataId, param.Group, clientConfig.NamespaceId)
				return "", nil
			}
			if nacosErr.ErrorCode() == "403" {
				return "", errors.New("get config forbidden")
			}
		}
		content, err = cache.ReadConfigFromFile(cacheKey, client.configCacheDir)
		if err != nil {
			logger.Errorf("get config from cache  error:%+v ", err)
			return "", errors.New("read config from both server and cache fail")
		}

	} else {
		cache.WriteConfigToFile(cacheKey, client.configCacheDir, content)
	}
	return content, nil
}

// 发布配置
func (client *ConfigClient) PublishConfig(param vo.ConfigParam) (published bool,
	err error) {
	if len(param.DataId) <= 0 {
		err = errors.New("[client.PublishConfig] param.dataId can not be empty")
	}
	if len(param.Group) <= 0 {
		err = errors.New("[client.PublishConfig] param.group can not be empty")
	}
	if len(param.Content) <= 0 {
		err = errors.New("[client.PublishConfig] param.content can not be empty")
	}

	param.Content, err = client.encrypt(param.DataId, param.Content)
	if err != nil {
		return false, err
	}
	clientConfig, _ := client.GetClientConfig()
	return client.configProxy.PublishConfigProxy(param, clientConfig.NamespaceId, clientConfig.AccessKey, clientConfig.SecretKey)
}

func (client *ConfigClient) DeleteConfig(param vo.ConfigParam) (deleted bool, err error) {
	if len(param.DataId) <= 0 {
		err = errors.New("[client.DeleteConfig] param.dataId can not be empty")
	}
	if len(param.Group) <= 0 {
		err = errors.New("[client.DeleteConfig] param.group can not be empty")
	}

	clientConfig, _ := client.GetClientConfig()
	return client.configProxy.DeleteConfigProxy(param, clientConfig.NamespaceId, clientConfig.AccessKey, clientConfig.SecretKey)
}

//Cancel Listen Config
func (client *ConfigClient) CancelListenConfig(param vo.ConfigParam) (err error) {
	clientConfig, err := client.GetClientConfig()
	if err != nil {
		logger.Errorf("[checkConfigInfo.GetClientConfig] failed,err:%+v", err)
		return
	}
	client.cacheMap.Remove(util.GetConfigCacheKey(param.DataId, param.Group, clientConfig.NamespaceId))
	logger.Infof("Cancel listen config DataId:%s Group:%s", param.DataId, param.Group)
	remakeId := int(math.Ceil(float64(client.cacheMap.Count()) / float64(perTaskConfigSize)))
	if remakeId < client.currentTaskCount {
		client.remakeCacheDataTaskId(remakeId)
	}
	return err
}

//Remake cache data taskId
func (client *ConfigClient) remakeCacheDataTaskId(remakeId int) {
	for i := 0; i < remakeId; i++ {
		count := 0
		for _, key := range client.cacheMap.Keys() {
			if count == perTaskConfigSize {
				break
			}
			if value, ok := client.cacheMap.Get(key); ok {
				cData := value.(cacheData)
				cData.taskId = i
				client.cacheMap.Set(key, cData)
			}
			count++
		}
	}
}

// 监听配置
// 此方法是向cacheMap中放入缓存数据，待定时任务listenConfigExecutor()从中获取后订阅配置信息的变化
func (client *ConfigClient) ListenConfig(param vo.ConfigParam) (err error) {
	if len(param.DataId) <= 0 {
		err = errors.New("[client.ListenConfig] DataId can not be empty")
		return err
	}
	if len(param.Group) <= 0 {
		err = errors.New("[client.ListenConfig] Group can not be empty")
		return err
	}
	clientConfig, err := client.GetClientConfig()
	if err != nil {
		err = errors.New("[checkConfigInfo.GetClientConfig] failed")
		return err
	}

	key := util.GetConfigCacheKey(param.DataId, param.Group, clientConfig.NamespaceId)
	var cData cacheData
	if v, ok := client.cacheMap.Get(key); ok {
		cData = v.(cacheData)
		cData.isInitializing = true
	} else {
		var (
			content string
			md5Str  string
		)
		// 从本地文件缓存中获取配置信息
		content, fileErr := cache.ReadConfigFromFile(key, client.configCacheDir)
		if fileErr != nil {
			logger.Errorf("[cache.ReadConfigFromFile] error: %+v", fileErr)
		}
		// 若本地文件缓存中有数据，作为数据缓存的初始值，并生成其md5值
		if len(content) > 0 {
			md5Str = util.Md5(content)
		}
		// 构建监听数据变化的Listener
		listener := &cacheDataListener{
			listener: param.OnChange, // OnChange func
			lastMd5:  md5Str,  // 配置md5
		}

		// 配置缓存数据
		cData = cacheData{
			isInitializing:    true,
			dataId:            param.DataId,
			group:             param.Group,
			tenant:            clientConfig.NamespaceId,
			content:           content,
			md5:               md5Str,
			cacheDataListener: listener,
			taskId:            client.cacheMap.Count() / perTaskConfigSize, // 当前监听所在任务Id，每3000个监控可在同一个任务
		}
	}
	// 向cacheMap放入数据
	// 如果cacheKey是首次被Listen，那么cData中的content、md5Str都是空串
	client.cacheMap.Set(key, cData)
	return
}

//Delay Scheduler 延迟调度器
//initialDelay the time to delay first execution
//delay the delay between the termination of one execution and the commencement of the next
func (client *ConfigClient) delayScheduler(t *time.Timer, delay time.Duration, taskId string, execute func() error) {
	for {
		if v, ok := client.schedulerMap.Get(taskId); ok {
			// schedulerMap的key=taskId，value=boolean 判断任务是否继续执行
			if !v.(bool) {
				return
			}
		}
		<-t.C // initialDelay 初始延迟
		d := delay // delay，默认10ms
		if err := execute(); err != nil {
			d = executorErrDelay // 发生错误，延迟5s下次执行
		}
		t.Reset(d)
	}
}

//Listen for the configuration executor
//root任务执行的func，用于通过cacheMap.Count()大小的判断，增加/减少长轮训任务的数量
func (client *ConfigClient) listenConfigExecutor() func() error {
	return func() error {
		listenerSize := client.cacheMap.Count()
		// 当前做Listener的任务数，每3000个监听可以共享一个task
		// math.Ceil向上进一
		taskCount := int(math.Ceil(float64(listenerSize) / float64(perTaskConfigSize)))

		// 如果taskCount已经超过configClient当前执行的任务数
		// 向schedulerMap中新增一条taskId:true
		// 并为任务开启delayScheduler延迟调度
		if taskCount > client.currentTaskCount {
			for i := client.currentTaskCount; i < taskCount; i++ {
				client.schedulerMap.Set(strconv.Itoa(i), true)
				go client.delayScheduler(time.NewTimer(1*time.Millisecond), 10*time.Millisecond, strconv.Itoa(i), client.longPulling(i))
			}
			client.currentTaskCount = taskCount
		} else if taskCount < client.currentTaskCount { // 减少任务数量，schedulerMap的value置为false
			for i := taskCount; i < client.currentTaskCount; i++ {
				if _, ok := client.schedulerMap.Get(strconv.Itoa(i)); ok {
					client.schedulerMap.Set(strconv.Itoa(i), false)
				}
			}
			client.currentTaskCount = taskCount
		}
		return nil
	}
}

// Long polling listening configuration
// 长轮训任务，默认每个任务可监听3000个cacheKey，长轮训30s超时
// 返回后，根据配置是否有变更，判断是否调用Listener
func (client *ConfigClient) longPulling(taskId int) func() error {
	return func() error {
		var listeningConfigs string  // 所有监听的配置
		initializationList := make([]cacheData, 0)
		for _, key := range client.cacheMap.Keys() {
			if value, ok := client.cacheMap.Get(key); ok {
				cData := value.(cacheData)
				// 监听数据被分配的taskId等于当前长轮训任务的taskId
				if cData.taskId == taskId {
					// 是否为新添加的cacheData监听数据
					if cData.isInitializing {
						initializationList = append(initializationList, cData)
					}
					if len(cData.tenant) > 0 {
						listeningConfigs += cData.dataId + constant.SPLIT_CONFIG_INNER + cData.group + constant.SPLIT_CONFIG_INNER +
							cData.md5 + constant.SPLIT_CONFIG_INNER + cData.tenant + constant.SPLIT_CONFIG
					} else {
						listeningConfigs += cData.dataId + constant.SPLIT_CONFIG_INNER + cData.group + constant.SPLIT_CONFIG_INNER +
							cData.md5 + constant.SPLIT_CONFIG
					}
				}
			}
		}
		// listeningConfigs是所有监听配置拼起来的字符串
		if len(listeningConfigs) > 0 {
			clientConfig, err := client.GetClientConfig()
			if err != nil {
				logger.Errorf("[checkConfigInfo.GetClientConfig] err: %+v", err)
				return err
			}
			// http get
			params := make(map[string]string)
			params[constant.KEY_LISTEN_CONFIGS] = listeningConfigs

			var changed string
			// len(initializationList) > 0, server端应该不会hang住请求，可能是返回当前最新的版本号
			changedTmp, err := client.configProxy.ListenConfig(params, len(initializationList) > 0, clientConfig.NamespaceId, clientConfig.AccessKey, clientConfig.SecretKey)
			if err == nil {
				changed = changedTmp
			} else {
				if _, ok := err.(*nacos_error.NacosError); ok {
					changed = changedTmp
				} else {
					logger.Errorf("[client.ListenConfig] listen config error: %+v", err)
				}
				return err
			}

			// 将initializationList中所有cacheData的isInitializing置为false
			// 即将原本新添加的cacheData数据置为非初始化状态
			for _, v := range initializationList {
				v.isInitializing = false
				client.cacheMap.Set(util.GetConfigCacheKey(v.dataId, v.group, v.tenant), v)
			}

			if len(strings.ToLower(strings.Trim(changed, " "))) == 0 {
				logger.Info("[client.ListenConfig] no change")
			} else { // 配置有变更，调用Listener
				logger.Info("[client.ListenConfig] config changed:" + changed)
				client.callListener(changed, clientConfig.NamespaceId)
			}
		}
		return nil
	}

}

// Execute the Listener callback func()
// 调用配置监听器
func (client *ConfigClient) callListener(changed, tenant string) {
	changedConfigs := strings.Split(changed, "%01")
	// 循环遍历所有配置发生变更的
	// 1、真正的获取最新的配置数据
	// 2、调用OnChange
	// 3、更新cache
	for _, config := range changedConfigs {
		attrs := strings.Split(config, "%02")
		if len(attrs) >= 2 {
			// 获取发生配置变更的cacheData
			// dataId=attrs[0], groupId=attrs[1]
			if value, ok := client.cacheMap.Get(util.GetConfigCacheKey(attrs[0], attrs[1], tenant)); ok {
				cData := value.(cacheData)
				// 真正的获取最新的配置数据
				content, err := client.getConfigInner(vo.ConfigParam{
					DataId: cData.dataId,
					Group:  cData.group,
				})
				if err != nil {
					logger.Errorf("[client.getConfigInner] DataId:[%s] Group:[%s] Error:[%+v]", cData.dataId, cData.group, err)
					continue
				}
				cData.content = content
				cData.md5 = util.Md5(content)
				// 配置的md5值发生变化
				if cData.md5 != cData.cacheDataListener.lastMd5 {
					// 调用OnChange
					go cData.cacheDataListener.listener(tenant, attrs[1], attrs[0], cData.content)
					cData.cacheDataListener.lastMd5 = cData.md5
					// 更新cache
					client.cacheMap.Set(util.GetConfigCacheKey(cData.dataId, cData.group, tenant), cData)
				}
			}
		}
	}
}

func (client *ConfigClient) buildBasePath(serverConfig constant.ServerConfig) (basePath string) {
	basePath = "http://" + serverConfig.IpAddr + ":" +
		strconv.FormatUint(serverConfig.Port, 10) + serverConfig.ContextPath + constant.CONFIG_PATH
	return
}

func (client *ConfigClient) SearchConfig(param vo.SearchConfigParam) (*model.ConfigPage, error) {
	return client.searchConfigInner(param)
}

func (client *ConfigClient) PublishAggr(param vo.ConfigParam) (published bool,
	err error) {
	if len(param.DataId) <= 0 {
		err = errors.New("[client.PublishAggr] param.dataId can not be empty")
	}
	if len(param.Group) <= 0 {
		err = errors.New("[client.PublishAggr] param.group can not be empty")
	}
	if len(param.Content) <= 0 {
		err = errors.New("[client.PublishAggr] param.content can not be empty")
	}
	if len(param.DatumId) <= 0 {
		err = errors.New("[client.PublishAggr] param.DatumId can not be empty")
	}
	clientConfig, _ := client.GetClientConfig()
	return client.configProxy.PublishAggProxy(param, clientConfig.NamespaceId, clientConfig.AccessKey, clientConfig.SecretKey)
}

func (client *ConfigClient) RemoveAggr(param vo.ConfigParam) (published bool,
	err error) {
	if len(param.DataId) <= 0 {
		err = errors.New("[client.DeleteAggr] param.dataId can not be empty")
	}
	if len(param.Group) <= 0 {
		err = errors.New("[client.DeleteAggr] param.group can not be empty")
	}
	if len(param.Content) <= 0 {
		err = errors.New("[client.DeleteAggr] param.content can not be empty")
	}
	if len(param.DatumId) <= 0 {
		err = errors.New("[client.DeleteAggr] param.DatumId can not be empty")
	}
	clientConfig, _ := client.GetClientConfig()
	return client.configProxy.DeleteAggProxy(param, clientConfig.NamespaceId, clientConfig.AccessKey, clientConfig.SecretKey)
}

func (client *ConfigClient) searchConfigInner(param vo.SearchConfigParam) (*model.ConfigPage, error) {
	if param.Search != "accurate" && param.Search != "blur" {
		return nil, errors.New("[client.searchConfigInner] param.search must be accurate or blur")
	}
	if param.PageNo <= 0 {
		param.PageNo = 1
	}
	if param.PageSize <= 0 {
		param.PageSize = 10
	}
	clientConfig, _ := client.GetClientConfig()
	configItems, err := client.configProxy.SearchConfigProxy(param, clientConfig.NamespaceId, clientConfig.AccessKey, clientConfig.SecretKey)
	if err != nil {
		logger.Errorf("search config from server error:%+v ", err)
		if _, ok := err.(*nacos_error.NacosError); ok {
			nacosErr := err.(*nacos_error.NacosError)
			if nacosErr.ErrorCode() == "404" {
				return nil, nil
			}
			if nacosErr.ErrorCode() == "403" {
				return nil, errors.New("get config forbidden")
			}
		}
		return nil, err
	}
	return configItems, nil
}
