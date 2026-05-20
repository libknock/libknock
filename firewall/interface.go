package firewall

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type Firewall interface {
	Allow(ctx context.Context, remote netip.Addr, port int, ttl time.Duration) error
	Revoke(ctx context.Context, remote netip.Addr, port int) error
}

type Backend interface {
	Firewall
	Name() string
	Init(ctx context.Context) error
	Cleanup(ctx context.Context) error
}

type ConfigurableBackend interface {
	Backend
	Config() Config
	WithConfig(Config) (Backend, error)
}

type ValidatingBackend interface {
	Validate() error
}

type Checker interface {
	IsAllowed(ctx context.Context, remote netip.Addr, port int) (bool, error)
}

type Config struct {
	Backend          string
	Port             int
	AllowSeconds     int
	CommandTimeout   time.Duration
	Runner           Runner
	DropUDPKnockPort bool
	UDPKnockPort     int
	EnableIPv6       *bool
	Nftables         NftablesConfig
	Iptables         IptablesConfig
	IPSet            IPSetConfig
	Script           ScriptConfig
}

const DefaultAllowSeconds = 15

func (c Config) WithDefaults() Config {
	if c.AllowSeconds <= 0 {
		c.AllowSeconds = DefaultAllowSeconds
	}
	return c
}

type NftablesConfig struct{ Table, Chain, SetV4, SetV6, Family string }
type IptablesConfig struct{ Chain string }
type IPSetConfig struct{ Set, SetV6 string }
type ScriptConfig struct{ AllowCmd, RevokeCmd, CleanupCmd string }

type Runner interface {
	Run(ctx context.Context, name string, args ...string) error
	RunInput(ctx context.Context, input, name string, args ...string) error
}

type Capabilities struct {
	Backend  string
	Commands map[string]string
	Timeout  bool
	DropUDP  bool
}

type ProbeResult struct {
	Capabilities
	EUID           int
	HasCAPNetAdmin bool
	HasCAPNetRaw   bool
}

type Noop struct{}

func (Noop) Name() string                                                { return "noop" }
func (Noop) Init(context.Context) error                                  { return nil }
func (Noop) Allow(context.Context, netip.Addr, int, time.Duration) error { return nil }
func (Noop) Revoke(context.Context, netip.Addr, int) error               { return nil }
func (Noop) Cleanup(context.Context) error                               { return nil }

func Validate(cfg Config) (Capabilities, error) {
	b, err := New(cfg)
	if err != nil {
		return Capabilities{}, err
	}
	if v, ok := b.(ValidatingBackend); ok {
		if err := v.Validate(); err != nil {
			return Capabilities{}, err
		}
	}
	return Describe(b.Name()), nil
}

func Probe(ctx context.Context, cfg Config) (ProbeResult, error) {
	b, err := New(cfg)
	if err != nil {
		return ProbeResult{}, err
	}
	if v, ok := b.(ValidatingBackend); ok {
		if err := v.Validate(); err != nil {
			return ProbeResult{}, err
		}
	}
	caps := Describe(b.Name())
	res := ProbeResult{Capabilities: caps, EUID: os.Geteuid(), HasCAPNetAdmin: hasEffectiveCapability(12), HasCAPNetRaw: hasEffectiveCapability(13)}
	switch b.Name() {
	case "nftables":
		if err := runWithConfig(ctx, cfg, "nft", "list", "ruleset"); err != nil {
			return res, err
		}
	case "iptables":
		if err := runIptables(ctx, cfg, "iptables", "-L", "INPUT", "-n"); err != nil {
			return res, err
		}
	case "ipset-iptables":
		if err := runWithConfig(ctx, cfg, "ipset", "list", "-name"); err != nil {
			return res, err
		}
		if err := runIptables(ctx, cfg, "iptables", "-L", "INPUT", "-n"); err != nil {
			return res, err
		}
	}
	return res, nil
}

func Describe(name string) Capabilities {
	c := Capabilities{Backend: name, Commands: make(map[string]string)}
	for _, cmd := range backendCommands(name) {
		if path, err := exec.LookPath(cmd); err == nil {
			c.Commands[cmd] = path
		}
	}
	switch name {
	case "nftables", "ipset-iptables":
		c.Timeout, c.DropUDP = true, true
	case "iptables":
		c.DropUDP = true
	}
	return c
}

func New(cfg Config) (Backend, error) {
	cfg = cfg.WithDefaults()
	name := cfg.Backend
	if name == "" {
		name = "auto"
	}
	if name == "auto" {
		detected, err := Detect(cfg)
		if err != nil {
			return nil, err
		}
		name = detected
	}
	switch name {
	case "noop":
		return Noop{}, nil
	case "nftables":
		if err := validateFirewallPort(cfg.Port, name); err != nil {
			return nil, err
		}
		if err := validateNftablesConfig(cfg.Nftables); err != nil {
			return nil, err
		}
		if !firewallCommandExists(cfg, "nft") {
			return nil, errors.New(`firewall backend nftables selected, but command "nft" was not found`)
		}
		return NewNftables(cfg, name), nil
	case "ipset-iptables":
		if err := validateFirewallPort(cfg.Port, name); err != nil {
			return nil, err
		}
		if err := validateIPSetIptablesConfig(cfg); err != nil {
			return nil, err
		}
		if !firewallCommandExists(cfg, "ipset") {
			return nil, errors.New(`firewall backend ipset-iptables selected, but command "ipset" was not found`)
		}
		if !firewallCommandExists(cfg, "iptables") {
			return nil, iptablesMissingError()
		}
		return NewIPSetIptables(cfg), nil
	case "iptables":
		if err := validateFirewallPort(cfg.Port, name); err != nil {
			return nil, err
		}
		if err := validateIptablesConfig(cfg.Iptables); err != nil {
			return nil, err
		}
		if !firewallCommandExists(cfg, "iptables") {
			return nil, iptablesMissingError()
		}
		return NewIptables(cfg), nil
	case "script":
		if err := validateFirewallPort(cfg.Port, name); err != nil {
			return nil, err
		}
		if cfg.Script.AllowCmd == "" || cfg.Script.RevokeCmd == "" || cfg.Script.CleanupCmd == "" {
			return nil, errors.New("firewall backend script requires allow_cmd, revoke_cmd, and cleanup_cmd")
		}
		if cfg.DropUDPKnockPort {
			return nil, errors.New("firewall backend script cannot manage drop_udp_knock_port; use nftables, iptables, ipset-iptables, or disable udp-passive")
		}
		return NewScript(cfg), nil
	default:
		return nil, fmt.Errorf("unknown firewall backend %q", name)
	}
}

func Detect(cfg Config) (string, error) {
	if runtime.GOOS != "linux" {
		if cfg.Script.AllowCmd != "" {
			return "script", nil
		}
		return "", fmt.Errorf("firewall backend auto is only supported on linux unless script backend is configured; current OS is %s", runtime.GOOS)
	}
	if firewallCommandExists(cfg, "nft") {
		return "nftables", nil
	}
	if firewallCommandExists(cfg, "ipset") && firewallCommandExists(cfg, "iptables") {
		return "ipset-iptables", nil
	}
	if firewallCommandExists(cfg, "iptables") {
		return "iptables", nil
	}
	if cfg.Script.AllowCmd != "" {
		return "script", nil
	}
	return "", errors.New("no usable firewall backend was detected; install nftables or iptables/ipset, or configure firewall backend script")
}

func backendCommands(name string) []string {
	switch name {
	case "nftables":
		return []string{"nft"}
	case "ipset-iptables":
		return []string{"ipset", "iptables", "ip6tables"}
	case "iptables":
		return []string{"iptables", "ip6tables"}
	default:
		return nil
	}
}

func WithPort(b Backend, port int) (Backend, error) {
	if b == nil {
		return nil, errors.New("firewall backend is nil")
	}
	if isNoopBackend(b) {
		return b, nil
	}
	if err := validateFirewallPort(port, b.Name()); err != nil {
		return nil, err
	}
	if configurable, ok := b.(ConfigurableBackend); ok {
		cfg := configurable.Config()
		cfg.Port = port
		return configurable.WithConfig(cfg)
	}
	return nil, fmt.Errorf("firewall backend %s does not support port injection", b.Name())
}

func isNoopBackend(b Backend) bool {
	switch b.(type) {
	case Noop, *Noop:
		return true
	default:
		return false
	}
}

func validateFirewallPort(port int, backend string) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("firewall backend %s requires protected port in 1..65535", backend)
	}
	return nil
}

func validateBoundFirewallPort(backend string, bound, got int) error {
	if err := validateFirewallPort(bound, backend); err != nil {
		return err
	}
	if got != bound {
		return fmt.Errorf("firewall backend %s is bound to protected port %d, got %d", backend, bound, got)
	}
	return nil
}

var (
	nftIdentifierRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)
	fwNameRE        = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,30}$`)
)

func validateNftablesConfig(cfg NftablesConfig) error {
	if cfg.Family != "" && cfg.Family != "inet" {
		return fmt.Errorf("only nftables family inet is supported, got %q", cfg.Family)
	}
	if cfg.Table != "" && !isSafeNftablesTable(cfg.Table) {
		return fmt.Errorf("unsafe nftables table %q: use a libknock-owned table such as knock_gateway or libknock_*", cfg.Table)
	}
	for label, value := range map[string]string{"table": cfg.Table, "chain": cfg.Chain, "set_v4": cfg.SetV4, "set_v6": cfg.SetV6} {
		if value != "" && !nftIdentifierRE.MatchString(value) {
			return fmt.Errorf("invalid nftables %s identifier %q", label, value)
		}
	}
	return nil
}

func isSafeNftablesTable(table string) bool {
	switch table {
	case "filter", "nat", "mangle", "raw", "security":
		return false
	}
	return table == "knock_gateway" || table == "knock_proxy" || strings.HasPrefix(table, "libknock_") || strings.HasPrefix(table, "knock_gateway_") || strings.HasPrefix(table, "knock_proxy_")
}

func ipv6Enabled(cfg Config, backend string) bool {
	if cfg.EnableIPv6 != nil {
		return *cfg.EnableIPv6
	}
	return firewallCommandExists(cfg, "ip6tables")
}

func validateIptablesConfig(cfg IptablesConfig) error {
	if cfg.Chain != "" {
		return validateFirewallObjectName("iptables chain", cfg.Chain)
	}
	return nil
}

func validateIPSetIptablesConfig(cfg Config) error {
	if err := validateIptablesConfig(cfg.Iptables); err != nil {
		return err
	}
	for label, value := range map[string]string{"ipset set": cfg.IPSet.Set, "ipset set_v6": cfg.IPSet.SetV6} {
		if value != "" {
			if err := validateFirewallObjectName(label, value); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateFirewallObjectName(label, value string) error {
	if strings.HasPrefix(value, "-") || strings.ContainsAny(value, " \t\n\r;{}") || !fwNameRE.MatchString(value) {
		return fmt.Errorf("invalid %s name %q", label, value)
	}
	return nil
}

func commandExists(name string) bool { _, err := exec.LookPath(name); return err == nil }

func firewallCommandExists(cfg Config, name string) bool {
	if cfg.Runner != nil {
		return cfg.Runner.Run(context.Background(), name, "--help") == nil || cfg.Runner.Run(context.Background(), name, "--version") == nil
	}
	return commandExists(name)
}

func run(ctx context.Context, name string, args ...string) error {
	return runWithConfig(ctx, Config{}, name, args...)
}

func runWithConfig(ctx context.Context, cfg Config, name string, args ...string) error {
	runner := cfg.Runner
	if runner == nil {
		runner = execRunner{timeout: commandTimeout(cfg)}
	}
	return runner.Run(ctx, name, args...)
}

func runInputWithConfig(ctx context.Context, cfg Config, input, name string, args ...string) error {
	runner := cfg.Runner
	if runner == nil {
		runner = execRunner{timeout: commandTimeout(cfg)}
	}
	return runner.RunInput(ctx, input, name, args...)
}

const defaultCommandTimeout = 5 * time.Second

func commandTimeout(cfg Config) time.Duration {
	if cfg.CommandTimeout > 0 {
		return cfg.CommandTimeout
	}
	return defaultCommandTimeout
}

type execRunner struct{ timeout time.Duration }

func (r execRunner) Run(ctx context.Context, name string, args ...string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s failed: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return nil
}

func (r execRunner) RunInput(ctx context.Context, input, name string, args ...string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = strings.NewReader(input)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s failed: %w: %s\ninput:\n%s", name, strings.Join(args, " "), err, strings.TrimSpace(string(output)), input)
	}
	return nil
}

func runIptables(ctx context.Context, cfg Config, name string, args ...string) error {
	return runWithConfig(ctx, cfg, name, append([]string{"-w", "5"}, args...)...)
}

func ignoreMissingFirewallObject(err error) error {
	if err == nil || isMissingFirewallObject(err) {
		return nil
	}
	return err
}

func isMissingFirewallObject(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	if strings.Contains(s, "no chain/target/match by that name") || strings.Contains(s, "permission denied") {
		return false
	}
	return strings.Contains(s, "does not exist") || strings.Contains(s, "no such file or directory") || strings.Contains(s, "not in set") || strings.Contains(s, "no such table") || strings.Contains(s, "it's not added") || strings.Contains(s, "bad rule (does a matching rule exist")
}

func ttlSeconds(ttl time.Duration) (int, error) {
	if ttl <= 0 {
		return 0, errors.New("firewall allow ttl must be positive")
	}
	seconds := int(ttl.Seconds())
	if seconds < 1 {
		seconds = 1
	}
	return seconds, nil
}

func hasEffectiveCapability(bit uint) bool {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return os.Geteuid() == 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "CapEff:") {
			fields := strings.Fields(line)
			if len(fields) != 2 {
				return false
			}
			v, err := strconv.ParseUint(fields[1], 16, 64)
			return err == nil && v&(uint64(1)<<bit) != 0
		}
	}
	return os.Geteuid() == 0
}

func iptablesMissingError() error {
	return errors.New(`firewall backend iptables selected, but command "iptables" was not found`)
}
func errIPv6Unsupported(backend string) error {
	return fmt.Errorf("firewall backend %s received an IPv6 client address, but command \"ip6tables\" was not found", backend)
}
func udpKnockPort(cfg Config) int {
	if cfg.UDPKnockPort > 0 {
		return cfg.UDPKnockPort
	}
	return cfg.Port
}
func toIP(addr netip.Addr) net.IP {
	if addr.Is4() {
		b := addr.As4()
		return net.IPv4(b[0], b[1], b[2], b[3])
	}
	if addr.Is6() {
		b := addr.As16()
		return net.IP(b[:])
	}
	return nil
}
