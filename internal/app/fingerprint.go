// 每账号客户端指纹（设备档案）—— 入池生成高可信桌面 SKU，一号一台设备。
//
// 默认不再克隆部署机。hub 跑在 Linux 云主机上，把 N 个账号都标成同一套
// 云内核 + 1920x1080，会在上游聚成「一台机房机器开了 N 个 ZCode」。官方
// 客户端是 Electron 桌面（darwin-arm64 / win32-x64 为主），账号身份必须
// 长得像用户电脑。
//
// 生成规则：
//   - 从成套 SKU 表抽样（platform × arch × os_version × screen 绑定），
//     禁止字段笛卡尔积（darwin-arm64 + 1366x768 这类假电脑）。
//   - 账号池不含 linux：官方桌面主形态是 Mac / Windows。
//   - 语言/时区取真实地区对；device_mid 每次全新 UUIDv4，跨账号不复用。
//   - 同账号档案一经分配即稳定；rotate() 换一整台 SKU（含新 MID）。
//
// host_profile 仍采集部署机，只给诊断/测试；不作为入池默认源。
// 存量非 SKU 档案（旧版宿主机克隆）由启动回填换成生成 SKU。
//
// 对齐 Python app/fingerprint.py。
package app

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"regexp"
	"strings"

	"github.com/zhaoboy9692/zcode2api-go/internal/uuidx"
)

type skuEntry struct {
	weight    int
	platform  string
	arch      string
	osVersion string
	screen    string
}

// 成套桌面 SKU：(weight, platform, arch, os_version, screen)
// 分辨率只取官方桌面端常见值，并与平台绑定（Mac 逻辑分辨率不配 Windows）。
var skus = []skuEntry{
	// Apple silicon MacBook Air/Pro 13–14"（darwin 24 = Sequoia，25 = Tahoe）
	{10, "darwin", "arm64", "24.5.0", "1512x982"},
	{10, "darwin", "arm64", "24.6.0", "1512x982"},
	{8, "darwin", "arm64", "24.5.0", "1728x1117"},
	{8, "darwin", "arm64", "24.6.0", "1728x1117"},
	{8, "darwin", "arm64", "25.5.0", "1512x982"},
	{6, "darwin", "arm64", "25.5.0", "1728x1117"},
	{5, "darwin", "arm64", "23.6.0", "1512x982"},
	{4, "darwin", "arm64", "23.6.0", "1728x1117"},
	{4, "darwin", "arm64", "24.5.0", "2560x1440"},
	{3, "darwin", "arm64", "24.6.0", "2560x1600"},
	{2, "darwin", "arm64", "25.5.0", "2560x1440"},
	{2, "darwin", "arm64", "24.5.0", "3840x2160"},
	// Intel Mac 存量（Ventura/Sonoma；darwin 24+ 不再配 x64）
	{2, "darwin", "x64", "23.6.0", "1920x1080"},
	{2, "darwin", "x64", "22.6.0", "1440x900"},
	{1, "darwin", "x64", "23.6.0", "2560x1440"},
	// Windows 11 主流 + 少量 Win10
	{8, "win32", "x64", "10.0.22631", "1920x1080"},
	{7, "win32", "x64", "10.0.26100", "1920x1080"},
	{5, "win32", "x64", "10.0.22631", "2560x1440"},
	{4, "win32", "x64", "10.0.26200", "1920x1080"},
	{3, "win32", "x64", "10.0.26100", "2560x1440"},
	{3, "win32", "x64", "10.0.22621", "1920x1080"},
	{2, "win32", "x64", "10.0.22631", "3840x2160"},
	{2, "win32", "x64", "10.0.19045", "1920x1080"},
	{1, "win32", "x64", "10.0.19045", "1366x768"},
	{1, "win32", "x64", "10.0.26100", "2560x1600"},
	{1, "win32", "x64", "10.0.22000", "1920x1080"},
}

// skuPool 按权重展开的抽样池（对齐 _SKU_POOL）。
var skuPool = func() [][4]string {
	var pool [][4]string
	for _, e := range skus {
		for i := 0; i < e.weight; i++ {
			pool = append(pool, [4]string{e.platform, e.arch, e.osVersion, e.screen})
		}
	}
	return pool
}()

// skuCombosSet 生成器允许的 (platform, arch, os_version, screen) 成套组合。
var skuCombosSet = func() map[[4]string]bool {
	set := map[[4]string]bool{}
	for _, c := range skuPool {
		set[c] = true
	}
	return set
}()

// SkuCombos 对齐 sku_combos()。
func SkuCombos() map[[4]string]bool { return skuCombosSet }

// host_real 校验仍认这些平台取值（部署机可能是 linux）
var (
	hostPlatforms = []string{"darwin", "win32", "linux"}
	hostArchs     = []string{"arm64", "x64"}
	osVersions    = map[string][]string{
		"darwin": {"22.6.0", "23.6.0", "24.5.0", "24.6.0", "25.5.0"},
		"win32":  {"10.0.19045", "10.0.22000", "10.0.22621", "10.0.22631", "10.0.26100", "10.0.26200"},
		"linux":  {"5.15.0-91-generic", "6.1.0-18-amd64", "6.8.0-45-generic"},
	}
	// 语言-时区真实地区组合（X-Client-Language ↔ X-Client-Timezone，激活事件同源）
	locales = [][2]string{
		{"zh-CN", "Asia/Shanghai"},
		{"en-US", "America/New_York"},
		{"en-US", "America/Los_Angeles"},
		{"en-GB", "Europe/London"},
		{"de-DE", "Europe/Berlin"},
		{"ja-JP", "Asia/Tokyo"},
		{"ko-KR", "Asia/Seoul"},
		{"en-SG", "Asia/Singapore"},
	}
)

var (
	screenRe    = regexp.MustCompile(`^\d{3,4}x\d{3,4}$`)
	// os.release() 形态门（host_real 放行用）：主版本.次版本.修订 + 可选后缀
	releaseShape = regexp.MustCompile(`^\d+\.\d+(\.\d+)?[\w.\-]*$`)
)

// DeviceProfile 单套客户端设备档案（所有值直接映射上游身份头/事件字段）。
type DeviceProfile struct {
	Platform  string // X-Platform 前半：darwin / win32 / linux
	Arch      string // arm64 / x64
	OSVersion string // X-Os-Version（os.release() 语义）
	Language  string // X-Client-Language
	Timezone  string // X-Client-Timezone（IANA）
	Screen    string // 激活事件 screen_resolution
	DeviceMid string // 每次全新 UUIDv4（Python default_factory）
}

// PlatformFull 对齐 .platform_full 属性。
func (p DeviceProfile) PlatformFull() string { return p.Platform + "-" + p.Arch }

// OsCategory 对齐 .os_category 属性：darwin→macos / win32→windows / 其它→linux。
func (p DeviceProfile) OsCategory() string {
	switch p.Platform {
	case "darwin", "macos":
		return "macos"
	case "win32", "windows":
		return "windows"
	default:
		return "linux"
	}
}

// IsGeneratedSku 档案是否为入池用的高可信桌面 SKU（旧版宿主机克隆为 false）。
func IsGeneratedSku(p DeviceProfile) bool {
	return skuCombosSet[[4]string{p.Platform, p.Arch, p.OSVersion, p.Screen}]
}

// Validate 合规校验：档案内部自洽（成套 SKU / 真机形态、地区对、分辨率、UUID）。
//
// hostReal=true 只用于宿主机采集：平台按取值形态放行（linux/arm64 云主机
// 等真实形态），os_version 放宽为内核版本形态。账号生成路径走严格 SKU 门。
func Validate(p DeviceProfile, hostReal bool) error {
	if hostReal {
		if !containsStr(hostPlatforms, p.Platform) || !containsStr(hostArchs, p.Arch) {
			return fmt.Errorf("非法平台形态: %s", p.PlatformFull())
		}
		known := false
		for _, v := range osVersions[p.Platform] {
			if v == p.OSVersion {
				known = true
				break
			}
		}
		if !known && !releaseShape.MatchString(p.OSVersion) {
			return fmt.Errorf("os_version 与平台不符: %s/%s", p.Platform, p.OSVersion)
		}
	} else {
		if !IsGeneratedSku(p) {
			return fmt.Errorf("非桌面 SKU: %s/%s/%s", p.PlatformFull(), p.OSVersion, p.Screen)
		}
		locOK := false
		for _, l := range locales {
			if l[0] == p.Language && l[1] == p.Timezone {
				locOK = true
				break
			}
		}
		if !locOK {
			return fmt.Errorf("语言/时区组合不真实: %s/%s", p.Language, p.Timezone)
		}
	}
	if !screenRe.MatchString(p.Screen) {
		return fmt.Errorf("分辨率形态非法: %s", p.Screen)
	}
	if !uuidx.IsValid(p.DeviceMid) { // 必须是合法 UUID
		return fmt.Errorf("device_mid 非法 UUID: %s", p.DeviceMid)
	}
	return nil
}

func containsStr(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// secretsChoice 对齐 secrets.choice(seq)。
func secretsChoice[T any](seq []T) T {
	n := big.NewInt(int64(len(seq)))
	idx, err := rand.Int(rand.Reader, n)
	if err != nil {
		panic(fmt.Sprintf("fingerprint: 随机源失败: %v", err))
	}
	return seq[idx.Int64()]
}

// RandomProfile 随机生成一份成套桌面 SKU 档案（生成时自校验）。
func RandomProfile() DeviceProfile {
	combo := secretsChoice(skuPool)
	locale := secretsChoice(locales)
	profile := DeviceProfile{
		Platform:  combo[0],
		Arch:      combo[1],
		OSVersion: combo[2],
		Language:  locale[0],
		Timezone:  locale[1],
		Screen:    combo[3],
		DeviceMid: uuidx.New4(),
	}
	if err := Validate(profile, false); err != nil {
		// Python 版同样直接抛出（生成表自身应始终合规）
		panic(fmt.Sprintf("fingerprint: 生成档案未通过校验: %v", err))
	}
	return profile
}

// ProfileFor 取账号档案：无则生成分配（幂等）。仅内存态分配，落库由调用方 save。
//
// Python 源里 fingerprint 字段可能是 DeviceProfile 或 dict（落库形态总是 dict），
// Go 版统一为 dict（map[string]any）。
func ProfileFor(a *Account) DeviceProfile {
	if a.Fingerprint != nil {
		if p, ok := profileFromDict(a.Fingerprint); ok {
			a.Fingerprint = profileToDict(p) // 对齐 Python：dict 形态还原为 DeviceProfile 后回写
			return p
		}
	}
	return AssignProfile(a)
}

// profileFromDict 从落库 dict 还原档案；缺 device_mid 视为未初始化。
func profileFromDict(fp map[string]any) (DeviceProfile, bool) {
	mid, _ := fp["device_mid"].(string)
	if mid == "" {
		return DeviceProfile{}, false
	}
	return DeviceProfile{
		Platform:  StrValue(fp["platform"]),
		Arch:      StrValue(fp["arch"]),
		OSVersion: StrValue(fp["os_version"]),
		Language:  StrValue(fp["language"]),
		Timezone:  StrValue(fp["timezone"]),
		Screen:    StrValue(fp["screen"]),
		DeviceMid: mid,
	}, true
}

func profileToDict(p DeviceProfile) map[string]any {
	return map[string]any{
		"platform":   p.Platform,
		"arch":       p.Arch,
		"os_version": p.OSVersion,
		"language":   p.Language,
		"timezone":   p.Timezone,
		"screen":     p.Screen,
		"device_mid": p.DeviceMid,
	}
}

// HostProfile 宿主机真实档案（诊断/测试用，不是入池默认源）。
//
// deviceMid 缺省 = DeviceProfile 缺省工厂的全新 UUID；传入
// quota.device_mid() 即「这台机器」语义。
func HostProfile(deviceMid string) DeviceProfile {
	profile := CollectHostProfile()
	if deviceMid != "" {
		profile.DeviceMid = deviceMid
	} else {
		profile.DeviceMid = uuidx.New4()
	}
	if err := Validate(profile, true); err != nil {
		panic(fmt.Sprintf("fingerprint: 宿主机档案未通过校验: %v", err))
	}
	return profile
}

// AssignProfile 入池分配档案：成套高可信桌面 SKU + 全新 device_mid（一号一台设备）。
func AssignProfile(a *Account) DeviceProfile {
	p := RandomProfile()
	a.Fingerprint = profileToDict(p)
	return p
}

// Rotate 换发全新档案（device_mid 必变；风控后换设备语义）。
//
// 换发换一整台成套 SKU（平台/内核/屏幕都可能变）+ 新 device_mid。
func Rotate(a *Account) DeviceProfile {
	p := RandomProfile()
	a.Fingerprint = profileToDict(p)
	return p
}

// ProfileDict 档案 → 落库 dict 形态（store._assign_fingerprint / rotate 后持久化用）。
func ProfileDict(p DeviceProfile) map[string]any { return profileToDict(p) }

// 引用 strings 防止未来裁剪（字符串工具集中地）
var _ = strings.TrimSpace
