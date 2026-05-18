package main

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/libknock/libknock/auth"
	"github.com/libknock/libknock/firewall"
	"github.com/libknock/libknock/knock"
	"gopkg.in/yaml.v3"
)

const (
	modeClient = "client"
	modeServer = "server"
)

type fileConfig struct {
	Mode      string          `yaml:"mode"`
	Client    clientConfig    `yaml:"client"`
	Server    serverConfig    `yaml:"server"`
	Access    accessConfig    `yaml:"access"`
	Knock     knockConfig     `yaml:"knock"`
	Auth      authConfig      `yaml:"auth"`
	Firewall  firewallConfig  `yaml:"firewall"`
	Transport transportConfig `yaml:"transport"`
	Limits    limitsConfig    `yaml:"limits"`
	Timeouts  timeoutsConfig  `yaml:"timeouts"`
	Metrics   metricsConfig   `yaml:"metrics"`
}

type clientConfig struct {
	Listen           string `yaml:"listen"`
	ServerAddr       string `yaml:"server_addr"`
	ProtectedTCPPort int    `yaml:"protected_tcp_port"`
	UDPServerAddr    string `yaml:"udp_server_addr"`
	ClientID         string `yaml:"client_id"`
	Secret           string `yaml:"secret"`
	SecretFile       string `yaml:"secret_file"`
}
type serverConfig struct {
	TCPListen string `yaml:"tcp_listen"`
	Upstream  string `yaml:"upstream"`
}
type accessConfig struct {
	Mode                    string `yaml:"mode"`
	RequireTCPAuth          *bool  `yaml:"require_tcp_auth"`
	RemoveAfterFirstConnect *bool  `yaml:"remove_after_first_connect"`
	MaxConnectionsPerKnock  int    `yaml:"max_connections_per_knock"`
}
type knockConfig struct {
	Method                string         `yaml:"method"`
	Frame                 string         `yaml:"frame"`
	MaxFrameSize          int            `yaml:"max_frame_size"`
	TimeWindow            string         `yaml:"time_window"`
	SequenceWindow        string         `yaml:"sequence_window"`
	SequenceMaxParts      int            `yaml:"sequence_max_parts"`
	RequireSessionBinding *bool          `yaml:"require_session_binding"`
	UDPListen             string         `yaml:"udp_listen"`
	UDPPort               int            `yaml:"udp_port"`
	UDPKnockPort          int            `yaml:"udp_knock_port"`
	TimeoutSeconds        int            `yaml:"timeout_seconds"`
	Retry                 int            `yaml:"retry"`
	TimeWindowSeconds     int            `yaml:"time_window_seconds"`
	Sequence              sequenceConfig `yaml:"sequence"`
	Replay                replayConfig   `yaml:"replay"`
}
type sequenceConfig struct {
	Length           int    `yaml:"length"`
	SlotSeconds      int    `yaml:"slot_seconds"`
	Window           string `yaml:"window"`
	PacketInterval   string `yaml:"packet_interval"`
	MaxJitter        string `yaml:"max_jitter"`
	MaxInflightPerIP int    `yaml:"max_inflight_per_ip"`
	MaxTotalInflight int    `yaml:"max_total_inflight"`
}
type replayConfig struct {
	NonceTTL string `yaml:"nonce_ttl"`
}
type authConfig struct {
	TimeWindowSeconds int          `yaml:"time_window_seconds"`
	NonceCacheSeconds int          `yaml:"nonce_cache_seconds"`
	Clients           []authClient `yaml:"clients"`
}
type authClient struct {
	ClientID       string `yaml:"client_id"`
	Secret         string `yaml:"secret"`
	SecretFile     string `yaml:"secret_file"`
	MaxConnections int    `yaml:"max_connections"`
}
type firewallConfig struct {
	Backend         string         `yaml:"backend"`
	Port            int            `yaml:"port"`
	DefaultAction   string         `yaml:"default_action"`
	AllowSeconds    int            `yaml:"allow_seconds"`
	RemoveAfterAuth bool           `yaml:"remove_after_auth"`
	Nftables        nftablesConfig `yaml:"nftables"`
	Iptables        iptablesConfig `yaml:"iptables"`
	IPSet           ipsetConfig    `yaml:"ipset"`
	Script          scriptConfig   `yaml:"script"`
}
type nftablesConfig struct {
	Table  string `yaml:"table"`
	Chain  string `yaml:"chain"`
	SetV4  string `yaml:"set_v4"`
	SetV6  string `yaml:"set_v6"`
	Family string `yaml:"family"`
}
type iptablesConfig struct {
	Chain string `yaml:"chain"`
}
type ipsetConfig struct {
	Set   string `yaml:"set"`
	SetV6 string `yaml:"set_v6"`
}
type scriptConfig struct {
	AllowCmd   string `yaml:"allow_cmd"`
	RevokeCmd  string `yaml:"revoke_cmd"`
	CleanupCmd string `yaml:"cleanup_cmd"`
}
type transportConfig struct {
	Encryption bool   `yaml:"encryption"`
	Method     string `yaml:"method"`
}
type limitsConfig struct {
	MaxPendingAuth int `yaml:"max_pending_auth"`
	MaxAuthWorkers int `yaml:"max_auth_workers"`
}
type timeoutsConfig struct {
	ConnectSeconds         int `yaml:"connect_seconds"`
	UpstreamConnectSeconds int `yaml:"upstream_connect_seconds"`
	AuthSeconds            int `yaml:"auth_seconds"`
	IdleSeconds            int `yaml:"idle_seconds"`
}
type metricsConfig struct {
	Enabled bool `yaml:"enabled"`
}

type serverRuntime struct {
	Listen, Upstream, KnockListen, KnockMethod string
	Port, KnockPort, MaxConnectionsPerKnock    int
	Secrets                                    map[string][]byte
	KnockClients                               []knock.ClientSecret
	Sequence                                   knock.SequenceOptions
	KnockTimeWindow, NonceTTL, AllowTTL        time.Duration
	KnockMaxFrameSize                          int
	AuthTimeWindow, NonceCacheTTL, AuthTimeout time.Duration
	UpstreamConnectTimeout, IdleTimeout        time.Duration
	RemoveAfterAuth                            bool
	DisableSessionBinding                      bool
	MaxPendingAuth, MaxAuthWorkers             int
	Firewall                                   firewall.Config
}

type clientRuntime struct {
	Listen, ServerAddr, UDPServerAddr, ClientID, KnockMethod                string
	Secret                                                                  []byte
	ServerPort, KnockRetry                                                  int
	Sequence                                                                knock.SequenceOptions
	KnockTimeout, KnockTimeWindow, ConnectTimeout, AuthTimeout, IdleTimeout time.Duration
	KnockMaxFrameSize                                                       int
}

func loadConfig(path string) (fileConfig, error) {
	cfg := defaultConfig()
	if path == "" {
		return cfg, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	if err := rejectLegacyKnockConfig(data); err != nil {
		return cfg, err
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func defaultConfig() fileConfig {
	return fileConfig{Access: accessConfig{Mode: "proxy", MaxConnectionsPerKnock: 1}, Knock: knockConfig{Frame: "binary-v1", MaxFrameSize: knock.DefaultMaxKnockFrameSize, TimeoutSeconds: 3, Retry: 2, TimeWindowSeconds: 30, SequenceMaxParts: knock.DefaultSequenceMaxParts, Sequence: sequenceConfig{Length: 3, SlotSeconds: 30, Window: "5s", PacketInterval: "80ms", MaxInflightPerIP: 8, MaxTotalInflight: 4096}, Replay: replayConfig{NonceTTL: "2m"}}, Auth: authConfig{TimeWindowSeconds: 30, NonceCacheSeconds: 300}, Firewall: firewallConfig{Backend: "auto", DefaultAction: "drop", AllowSeconds: 15, RemoveAfterAuth: true, Nftables: nftablesConfig{Table: "knock_proxy", Chain: "input", SetV4: "allowed_clients_v4", SetV6: "allowed_clients_v6", Family: "inet"}, Iptables: iptablesConfig{Chain: "KNOCK_PROXY"}, IPSet: ipsetConfig{Set: "knock_proxy_allowed", SetV6: "knock_proxy_allowed_v6"}}, Transport: transportConfig{Method: "chacha20-poly1305"}, Limits: limitsConfig{MaxPendingAuth: 128, MaxAuthWorkers: 32}, Timeouts: timeoutsConfig{ConnectSeconds: 5, UpstreamConnectSeconds: 5, AuthSeconds: 5, IdleSeconds: 300}}
}

func rejectLegacyKnockConfig(data []byte) error {
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return err
	}
	for _, path := range [][]string{{"knock", "frame"}, {"knock_frame_format"}, {"legacy_json"}, {"allow_json_knock"}, {"json_compat"}, {"json_sequence_compat"}} {
		n, ok := yamlPath(&root, path...)
		if !ok {
			continue
		}
		if len(path) == 2 && path[0] == "knock" && path[1] == "frame" && n.Value != "json" && n.Value != "legacy-json" {
			continue
		}
		return fmt.Errorf("unsupported legacy UDP knock config %q; binary-v1 is required", strings.Join(path, "."))
	}
	return nil
}

func yamlPath(n *yaml.Node, path ...string) (*yaml.Node, bool) {
	if n == nil {
		return nil, false
	}
	if n.Kind == yaml.DocumentNode && len(n.Content) > 0 {
		n = n.Content[0]
	}
	for _, key := range path {
		if n.Kind != yaml.MappingNode {
			return nil, false
		}
		found := false
		for i := 0; i+1 < len(n.Content); i += 2 {
			if n.Content[i].Value == key {
				n = n.Content[i+1]
				found = true
				break
			}
		}
		if !found {
			return nil, false
		}
	}
	return n, true
}

func (c fileConfig) serverRuntime() (serverRuntime, error) {
	if c.Mode != "" && c.Mode != modeServer {
		return serverRuntime{}, fmt.Errorf("config mode must be %q for server", modeServer)
	}
	if c.Transport.Encryption {
		return serverRuntime{}, errors.New("compatibility cmd does not terminate the old encrypted transport; disable transport.encryption or use the full knock-proxy product")
	}
	if c.Transport.Method != "" && c.Transport.Method != "chacha20-poly1305" {
		return serverRuntime{}, fmt.Errorf("compatibility cmd does not support transport.method %q", c.Transport.Method)
	}
	if c.Metrics.Enabled {
		return serverRuntime{}, errors.New("compatibility cmd does not host a metrics HTTP server; wire observability/prometheus from an embedding application")
	}
	if err := validateKnockBinaryConfig(c.Knock); err != nil {
		return serverRuntime{}, err
	}
	if defaultString(c.Access.Mode, "proxy") != "proxy" {
		return serverRuntime{}, errors.New("compatibility cmd server supports access.mode=proxy only")
	}
	if c.Access.RequireTCPAuth != nil && !*c.Access.RequireTCPAuth {
		return serverRuntime{}, errors.New("compatibility cmd server requires access.require_tcp_auth=true; disable the full relay product feature or use the standalone knock-proxy")
	}
	if c.Server.TCPListen == "" {
		return serverRuntime{}, errors.New("server.tcp_listen is required")
	}
	if c.Server.Upstream == "" {
		return serverRuntime{}, errors.New("server.upstream is required")
	}
	_, listenPort, err := splitHostPort(c.Server.TCPListen)
	if err != nil {
		return serverRuntime{}, fmt.Errorf("server.tcp_listen: %w", err)
	}
	if _, _, err := splitHostPort(c.Server.Upstream); err != nil {
		return serverRuntime{}, fmt.Errorf("server.upstream: %w", err)
	}
	port := c.Firewall.Port
	if port == 0 {
		port = listenPort
	}
	if port != listenPort {
		return serverRuntime{}, fmt.Errorf("firewall.port (%d) must match server.tcp_listen port (%d)", port, listenPort)
	}
	method := normalizeKnockMethod(defaultString(c.Knock.Method, "tcp-syn"))
	if !isKnockMethod(method) {
		return serverRuntime{}, fmt.Errorf("unsupported knock.method %q", method)
	}
	udpListen, udpPort, err := resolveUDPListen(c.Knock, c.Server.TCPListen)
	if err != nil {
		return serverRuntime{}, err
	}
	seq, nonceTTL, err := sequenceOptions(c.Knock)
	if err != nil {
		return serverRuntime{}, err
	}
	knockWindow, err := knockTimeWindow(c.Knock)
	if err != nil {
		return serverRuntime{}, err
	}
	maxFrameSize, err := knockMaxFrameSize(c.Knock)
	if err != nil {
		return serverRuntime{}, err
	}
	secrets := make(map[string][]byte, len(c.Auth.Clients))
	clients := make([]knock.ClientSecret, 0, len(c.Auth.Clients))
	for _, client := range c.Auth.Clients {
		if client.MaxConnections != 0 {
			return serverRuntime{}, errors.New("auth.clients[].max_connections is not supported by the compatibility cmd; use access.max_connections_per_knock")
		}
		if client.ClientID == "" {
			return serverRuntime{}, errors.New("auth.clients contains empty client_id")
		}
		if _, ok := secrets[client.ClientID]; ok {
			return serverRuntime{}, fmt.Errorf("duplicate auth client_id %q", client.ClientID)
		}
		secret, err := parseSecret(client.Secret, client.SecretFile)
		if err != nil {
			return serverRuntime{}, fmt.Errorf("auth.clients[%s].secret: %w", client.ClientID, err)
		}
		secrets[client.ClientID] = secret
		clients = append(clients, knock.ClientSecret{ClientID: client.ClientID, Secret: secret})
	}
	if len(secrets) == 0 {
		return serverRuntime{}, errors.New("auth.clients must contain at least one client")
	}
	fw := firewallConfigToLib(c.Firewall)
	fw.Port = port
	fw.UDPKnockPort = udpPort
	if fw.Backend == "" {
		fw.Backend = "auto"
	}
	if defaultString(c.Firewall.DefaultAction, "drop") != "drop" {
		return serverRuntime{}, errors.New("firewall.default_action must be drop")
	}
	if method == knock.UDPPassiveMethod || method == knock.UDPPassiveSeq {
		fw.DropUDPKnockPort = true
	}
	removeAfterAuth := c.Firewall.RemoveAfterAuth
	if c.Access.RemoveAfterFirstConnect != nil {
		removeAfterAuth = *c.Access.RemoveAfterFirstConnect
	}
	maxConnectionsPerKnock := defaultInt(c.Access.MaxConnectionsPerKnock, 1)
	if removeAfterAuth && maxConnectionsPerKnock > 1 {
		return serverRuntime{}, errors.New("remove_after_auth=true conflicts with max_connections_per_knock > 1")
	}
	disableSessionBinding := c.Knock.RequireSessionBinding != nil && !*c.Knock.RequireSessionBinding
	return serverRuntime{Listen: c.Server.TCPListen, Upstream: c.Server.Upstream, Port: port, KnockMethod: method, KnockListen: udpListen, KnockPort: udpPort, Secrets: secrets, KnockClients: clients, Sequence: seq, KnockTimeWindow: knockWindow, KnockMaxFrameSize: maxFrameSize, NonceTTL: nonceTTL, AllowTTL: seconds(defaultInt(c.Firewall.AllowSeconds, 15)), AuthTimeWindow: seconds(defaultInt(c.Auth.TimeWindowSeconds, 30)), NonceCacheTTL: seconds(defaultInt(c.Auth.NonceCacheSeconds, 300)), AuthTimeout: seconds(defaultInt(c.Timeouts.AuthSeconds, 5)), UpstreamConnectTimeout: seconds(defaultInt(c.Timeouts.UpstreamConnectSeconds, defaultInt(c.Timeouts.ConnectSeconds, 5))), IdleTimeout: seconds(defaultInt(c.Timeouts.IdleSeconds, 300)), RemoveAfterAuth: removeAfterAuth, DisableSessionBinding: disableSessionBinding, MaxConnectionsPerKnock: maxConnectionsPerKnock, MaxPendingAuth: defaultInt(c.Limits.MaxPendingAuth, 128), MaxAuthWorkers: defaultInt(c.Limits.MaxAuthWorkers, 32), Firewall: fw}, nil
}

func (c fileConfig) clientRuntime() (clientRuntime, error) {
	if c.Mode != "" && c.Mode != modeClient {
		return clientRuntime{}, fmt.Errorf("config mode must be %q for client", modeClient)
	}
	if c.Transport.Encryption {
		return clientRuntime{}, errors.New("compatibility cmd does not implement the old encrypted transport; disable transport.encryption or use the full knock-proxy product")
	}
	if c.Transport.Method != "" && c.Transport.Method != "chacha20-poly1305" {
		return clientRuntime{}, fmt.Errorf("compatibility cmd does not support transport.method %q", c.Transport.Method)
	}
	if err := validateKnockBinaryConfig(c.Knock); err != nil {
		return clientRuntime{}, err
	}
	if c.Client.Listen == "" {
		return clientRuntime{}, errors.New("client.listen is required")
	}
	if err := validateAddress("client.listen", c.Client.Listen); err != nil {
		return clientRuntime{}, err
	}
	if c.Client.ServerAddr == "" {
		return clientRuntime{}, errors.New("client.server_addr is required")
	}
	host, serverPort, err := splitHostPort(c.Client.ServerAddr)
	if err != nil {
		return clientRuntime{}, fmt.Errorf("client.server_addr: %w", err)
	}
	protectedPort := serverPort
	if c.Client.ProtectedTCPPort > 0 {
		protectedPort = c.Client.ProtectedTCPPort
	}
	if protectedPort < 1 || protectedPort > 65535 {
		return clientRuntime{}, fmt.Errorf("client.protected_tcp_port (%d) is invalid", protectedPort)
	}
	udpAddr := c.Client.ServerAddr
	if c.Client.UDPServerAddr != "" {
		if _, _, err := splitHostPort(c.Client.UDPServerAddr); err != nil {
			return clientRuntime{}, fmt.Errorf("client.udp_server_addr: %w", err)
		}
		udpAddr = c.Client.UDPServerAddr
	}
	udpPort := c.Knock.UDPKnockPort
	if udpPort == 0 {
		udpPort = c.Knock.UDPPort
	}
	if udpPort < 0 || udpPort > 65535 {
		return clientRuntime{}, fmt.Errorf("knock.udp_knock_port (%d) is invalid", udpPort)
	}
	if udpPort > 0 {
		udpAddr = net.JoinHostPort(host, strconv.Itoa(udpPort))
	}
	method := normalizeKnockMethod(defaultString(c.Knock.Method, defaultClientKnockMethod(runtime.GOOS)))
	if !isKnockMethod(method) {
		return clientRuntime{}, fmt.Errorf("unsupported knock.method %q", method)
	}
	if c.Client.ClientID == "" {
		return clientRuntime{}, errors.New("client.client_id is required")
	}
	secret, err := parseSecret(c.Client.Secret, c.Client.SecretFile)
	if err != nil {
		return clientRuntime{}, fmt.Errorf("client.secret: %w", err)
	}
	seq, _, err := sequenceOptions(c.Knock)
	if err != nil {
		return clientRuntime{}, err
	}
	knockWindow, err := knockTimeWindow(c.Knock)
	if err != nil {
		return clientRuntime{}, err
	}
	maxFrameSize, err := knockMaxFrameSize(c.Knock)
	if err != nil {
		return clientRuntime{}, err
	}
	return clientRuntime{Listen: c.Client.Listen, ServerAddr: c.Client.ServerAddr, UDPServerAddr: udpAddr, ClientID: c.Client.ClientID, Secret: secret, ServerPort: protectedPort, KnockMethod: method, KnockRetry: defaultInt(c.Knock.Retry, 2), Sequence: seq, KnockTimeout: seconds(defaultInt(c.Knock.TimeoutSeconds, 3)), KnockTimeWindow: knockWindow, KnockMaxFrameSize: maxFrameSize, ConnectTimeout: seconds(defaultInt(c.Timeouts.ConnectSeconds, 5)), AuthTimeout: seconds(defaultInt(c.Timeouts.AuthSeconds, 5)), IdleTimeout: seconds(defaultInt(c.Timeouts.IdleSeconds, 300))}, nil
}

func parseSecret(value, file string) ([]byte, error) {
	if file != "" {
		data, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		value = strings.TrimSpace(string(data))
	}
	if value == "" {
		return nil, errors.New("secret is required")
	}
	var out []byte
	var err error
	decoded := false
	switch {
	case strings.HasPrefix(value, "base64:"):
		raw := strings.TrimPrefix(value, "base64:")
		out, err = base64.StdEncoding.DecodeString(raw)
		if err != nil {
			out, err = base64.RawStdEncoding.DecodeString(raw)
		}
		decoded = true
	case strings.HasPrefix(value, "hex:"):
		out, err = hex.DecodeString(strings.TrimPrefix(value, "hex:"))
		decoded = true
	default:
		out = []byte(value)
	}
	if err != nil {
		return nil, err
	}
	if len(out) < auth.MinSecretSize {
		return nil, fmt.Errorf("secret must be at least %d bytes", auth.MinSecretSize)
	}
	if decoded {
		defer clearBytes(out)
		return append([]byte(nil), out...), nil
	}
	return out, nil
}

func clearBytes(buf []byte) {
	for i := range buf {
		buf[i] = 0
	}
}

func validateKnockBinaryConfig(k knockConfig) error {
	frame := defaultString(k.Frame, "binary-v1")
	if frame != "binary-v1" {
		return fmt.Errorf("knock.frame must be binary-v1, got %q", frame)
	}
	return nil
}

func knockTimeWindow(k knockConfig) (time.Duration, error) {
	if k.TimeWindow != "" {
		window, err := time.ParseDuration(k.TimeWindow)
		if err != nil {
			return 0, fmt.Errorf("knock.time_window: %w", err)
		}
		if window <= 0 {
			return 0, errors.New("knock.time_window must be positive")
		}
		return window, nil
	}
	return seconds(defaultInt(k.TimeWindowSeconds, 30)), nil
}

func knockMaxFrameSize(k knockConfig) (int, error) {
	max := defaultInt(k.MaxFrameSize, knock.DefaultMaxKnockFrameSize)
	if max < knock.KnockFrameHeaderSize || max > 65535 {
		return 0, fmt.Errorf("knock.max_frame_size must be between %d and 65535", knock.KnockFrameHeaderSize)
	}
	return max, nil
}

func sequenceOptions(k knockConfig) (knock.SequenceOptions, time.Duration, error) {
	s, r := k.Sequence, k.Replay
	maxParts := defaultInt(k.SequenceMaxParts, knock.DefaultSequenceMaxParts)
	if maxParts < 2 || maxParts > knock.DefaultSequenceMaxParts {
		return knock.SequenceOptions{}, 0, fmt.Errorf("knock.sequence_max_parts must be between 2 and %d", knock.DefaultSequenceMaxParts)
	}
	length := defaultInt(s.Length, 3)
	if length < 2 || length > maxParts {
		return knock.SequenceOptions{}, 0, fmt.Errorf("knock.sequence.length must be between 2 and %d", maxParts)
	}
	slot := defaultInt(s.SlotSeconds, 30)
	if slot < 5 {
		return knock.SequenceOptions{}, 0, errors.New("knock.sequence.slot_seconds must be at least 5")
	}
	windowText := s.Window
	if k.SequenceWindow != "" {
		windowText = k.SequenceWindow
	}
	window, err := parseDurationDefault(windowText, 5*time.Second)
	if err != nil {
		return knock.SequenceOptions{}, 0, fmt.Errorf("knock.sequence.window: %w", err)
	}
	interval, err := parseDurationDefault(s.PacketInterval, 80*time.Millisecond)
	if err != nil {
		return knock.SequenceOptions{}, 0, fmt.Errorf("knock.sequence.packet_interval: %w", err)
	}
	jitter, err := parseDurationDefault(s.MaxJitter, 0)
	if err != nil {
		return knock.SequenceOptions{}, 0, fmt.Errorf("knock.sequence.max_jitter: %w", err)
	}
	nonceTTL, err := parseDurationDefault(r.NonceTTL, 2*time.Minute)
	if err != nil {
		return knock.SequenceOptions{}, 0, fmt.Errorf("knock.replay.nonce_ttl: %w", err)
	}
	if nonceTTL <= window {
		return knock.SequenceOptions{}, 0, errors.New("knock.replay.nonce_ttl must be greater than knock.sequence.window")
	}
	return knock.SequenceOptions{Length: length, SlotSeconds: slot, Window: window, PacketInterval: interval, MaxJitter: jitter, MaxInflightPerIP: defaultInt(s.MaxInflightPerIP, 8), MaxTotalInflight: defaultInt(s.MaxTotalInflight, 4096)}, nonceTTL, nil
}

func firewallConfigToLib(c firewallConfig) firewall.Config {
	return firewall.Config{Backend: c.Backend, Port: c.Port, AllowSeconds: c.AllowSeconds, Nftables: firewall.NftablesConfig{Table: c.Nftables.Table, Chain: c.Nftables.Chain, SetV4: c.Nftables.SetV4, SetV6: c.Nftables.SetV6, Family: c.Nftables.Family}, Iptables: firewall.IptablesConfig{Chain: c.Iptables.Chain}, IPSet: firewall.IPSetConfig{Set: c.IPSet.Set, SetV6: c.IPSet.SetV6}, Script: firewall.ScriptConfig{AllowCmd: c.Script.AllowCmd, RevokeCmd: c.Script.RevokeCmd, CleanupCmd: c.Script.CleanupCmd}}
}

func resolveUDPListen(k knockConfig, tcpListen string) (string, int, error) {
	host, tcpPort, err := splitHostPort(tcpListen)
	if err != nil {
		return "", 0, fmt.Errorf("server.tcp_listen: %w", err)
	}
	udpPort := k.UDPKnockPort
	if udpPort == 0 {
		udpPort = k.UDPPort
	}
	if udpPort < 0 || udpPort > 65535 {
		return "", 0, fmt.Errorf("knock.udp_knock_port (%d) is invalid", udpPort)
	}
	if k.UDPListen != "" {
		_, parsed, err := splitHostPort(k.UDPListen)
		if err != nil {
			return "", 0, fmt.Errorf("knock.udp_listen: %w", err)
		}
		if udpPort == 0 {
			udpPort = parsed
		}
		return k.UDPListen, udpPort, nil
	}
	if udpPort == 0 {
		udpPort = tcpPort
	}
	return net.JoinHostPort(host, strconv.Itoa(udpPort)), udpPort, nil
}

func splitHostPort(addr string) (string, int, error) {
	host, p, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, err
	}
	port, err := strconv.Atoi(p)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("invalid port %q", p)
	}
	return host, port, nil
}
func validateAddress(name, addr string) error {
	host, _, err := splitHostPort(addr)
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	if strings.TrimSpace(host) == "" {
		return fmt.Errorf("%s: host is empty", name)
	}
	return nil
}
func parseDurationDefault(v string, d time.Duration) (time.Duration, error) {
	if v == "" {
		return d, nil
	}
	return time.ParseDuration(v)
}
func seconds(v int) time.Duration { return time.Duration(v) * time.Second }
func defaultInt(v, fallback int) int {
	if v == 0 {
		return fallback
	}
	return v
}
func defaultString(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}
func normalizeKnockMethod(method string) string {
	switch method {
	case "udp-sequence":
		return knock.UDPSeqMethod
	case "udp-passive-sequence":
		return knock.UDPPassiveSeq
	default:
		return method
	}
}
func isKnockMethod(method string) bool {
	switch method {
	case knock.TCPSYNMethod, knock.UDPMethod, knock.UDPPassiveMethod, knock.UDPSeqMethod, knock.UDPPassiveSeq, knock.TCP_SYNSeqMethod:
		return true
	default:
		return false
	}
}
func defaultClientKnockMethod(goos string) string {
	if goos == "windows" || goos == "darwin" {
		return knock.UDPMethod
	}
	return knock.TCPSYNMethod
}
