package killswitch

import (
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"sync"
)

// KillSwitch enforces fail-closed network traffic isolation to prevent cleartext data leaks
type KillSwitch interface {
	Enable(vpnServerIP string, vpnServerPort int, vpnInterface string) error
	Disable() error
	IsEnabled() bool
}

// Config parameters for killswitch activation
type Config struct {
	VPNServerIP   string
	VPNServerPort int
	VPNInterface  string
	AllowLAN      bool
	BlockIPv6     bool
}

type LinuxKillSwitch struct {
	mu      sync.Mutex
	enabled bool
	cfg     Config
	useNft  bool
}

func NewKillSwitch() KillSwitch {
	if runtime.GOOS == "linux" {
		useNft := false
		if _, err := exec.LookPath("nft"); err == nil {
			useNft = true
		}
		return &LinuxKillSwitch{useNft: useNft}
	}
	return &StubKillSwitch{}
}

func (k *LinuxKillSwitch) IsEnabled() bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.enabled
}

// Enable establishes fail-closed iptables/nftables firewall rules
func (k *LinuxKillSwitch) Enable(vpnServerIP string, vpnServerPort int, vpnInterface string) error {
	k.mu.Lock()
	defer k.mu.Unlock()

	if k.enabled {
		return nil
	}

	if vpnServerIP == "" || vpnServerPort <= 0 {
		return errors.New("invalid vpn server destination for killswitch")
	}

	k.cfg = Config{
		VPNServerIP:   vpnServerIP,
		VPNServerPort: vpnServerPort,
		VPNInterface:  vpnInterface,
		AllowLAN:      true,
		BlockIPv6:     true,
	}

	var err error
	if k.useNft {
		err = k.applyNftables()
	} else {
		err = k.applyIptables()
	}

	if err != nil {
		// Attempt rollback on failure to prevent locking the user out
		_ = k.cleanup()
		return fmt.Errorf("failed to enable killswitch: %w", err)
	}

	k.enabled = true
	return nil
}

// Disable restores normal networking
func (k *LinuxKillSwitch) Disable() error {
	k.mu.Lock()
	defer k.mu.Unlock()

	if !k.enabled {
		return nil
	}

	err := k.cleanup()
	k.enabled = false
	return err
}

func (k *LinuxKillSwitch) applyIptables() error {
	commands := [][]string{
		// 1. Drop IPv6 completely to prevent IPv6 leakage if tunnel is IPv4-only
		{"ip6tables", "-P", "INPUT", "DROP"},
		{"ip6tables", "-P", "OUTPUT", "DROP"},
		{"ip6tables", "-P", "FORWARD", "DROP"},

		// 2. Setup Freedom Cry Killswitch chain in IPv4
		{"iptables", "-N", "FC_KILLSWITCH"},
		{"iptables", "-F", "FC_KILLSWITCH"},

		// Allow loopback
		{"iptables", "-A", "FC_KILLSWITCH", "-o", "lo", "-j", "ACCEPT"},

		// Allow established/related connections
		{"iptables", "-A", "FC_KILLSWITCH", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"},

		// Allow LAN private subnets if enabled
		{"iptables", "-A", "FC_KILLSWITCH", "-d", "10.0.0.0/8", "-j", "ACCEPT"},
		{"iptables", "-A", "FC_KILLSWITCH", "-d", "172.16.0.0/12", "-j", "ACCEPT"},
		{"iptables", "-A", "FC_KILLSWITCH", "-d", "192.168.0.0/16", "-j", "ACCEPT"},
		{"iptables", "-A", "FC_KILLSWITCH", "-d", "224.0.0.0/4", "-j", "ACCEPT"},
		{"iptables", "-A", "FC_KILLSWITCH", "-d", "255.255.255.255/32", "-j", "ACCEPT"},

		// Allow connection to VPN Server endpoint
		{"iptables", "-A", "FC_KILLSWITCH", "-d", k.cfg.VPNServerIP, "-p", "udp", "--dport", fmt.Sprintf("%d", k.cfg.VPNServerPort), "-j", "ACCEPT"},
		{"iptables", "-A", "FC_KILLSWITCH", "-d", k.cfg.VPNServerIP, "-p", "tcp", "--dport", fmt.Sprintf("%d", k.cfg.VPNServerPort), "-j", "ACCEPT"},

		// Allow all traffic through VPN interface
		{"iptables", "-A", "FC_KILLSWITCH", "-o", k.cfg.VPNInterface, "-j", "ACCEPT"},

		// Block everything else
		{"iptables", "-A", "FC_KILLSWITCH", "-j", "DROP"},

		// Insert jump rule at the top of OUTPUT
		{"iptables", "-I", "OUTPUT", "1", "-j", "FC_KILLSWITCH"},
	}

	for _, cmdArgs := range commands {
		cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("command %v failed (%s): %w", cmdArgs, string(out), err)
		}
	}
	return nil
}

func (k *LinuxKillSwitch) applyNftables() error {
	nftConfig := fmt.Sprintf(`table inet fc_killswitch {
	chain output {
		type filter hook output priority 0; policy drop;

		oif "lo" accept
		ct state { established, related } accept

		ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 255.255.255.255 } accept

		ip daddr %s udp dport %d accept
		ip daddr %s tcp dport %d accept

		oif "%s" accept
	}
}`, k.cfg.VPNServerIP, k.cfg.VPNServerPort, k.cfg.VPNServerIP, k.cfg.VPNServerPort, k.cfg.VPNInterface)

	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(nftConfig)
	if _, err := cmd.CombinedOutput(); err != nil {
		// If nftables fails, fallback to iptables
		k.useNft = false
		return k.applyIptables()
	}
	return nil
}

func (k *LinuxKillSwitch) cleanup() error {
	if k.useNft {
		cmd := exec.Command("nft", "delete", "table", "inet", "fc_killswitch")
		_ = cmd.Run()
	}

	// Clean iptables
	_ = exec.Command("iptables", "-D", "OUTPUT", "-j", "FC_KILLSWITCH").Run()
	_ = exec.Command("iptables", "-F", "FC_KILLSWITCH").Run()
	_ = exec.Command("iptables", "-X", "FC_KILLSWITCH").Run()

	// Restore IPv6 default policy
	_ = exec.Command("ip6tables", "-P", "INPUT", "ACCEPT").Run()
	_ = exec.Command("ip6tables", "-P", "OUTPUT", "ACCEPT").Run()
	_ = exec.Command("ip6tables", "-P", "FORWARD", "ACCEPT").Run()

	return nil
}

// StubKillSwitch is used for non-Linux OS or fallback environments
type StubKillSwitch struct {
	mu      sync.Mutex
	enabled bool
}

func (s *StubKillSwitch) Enable(vpnServerIP string, vpnServerPort int, vpnInterface string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.enabled = true
	return nil
}

func (s *StubKillSwitch) Disable() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.enabled = false
	return nil
}

func (s *StubKillSwitch) IsEnabled() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.enabled
}
