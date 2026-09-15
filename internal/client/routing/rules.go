package routing

import (
	"net"
	"strings"
)

type RouteAction string

const (
	ActionDirect RouteAction = "direct"
	ActionTunnel RouteAction = "tunnel"
)

// Russian domestic TLDs and known direct infrastructure
var russianTLDs = []string{
	".ru",
	".su",
	".рф",
	".xn--p1ai",
}

// Key domestic domains that must bypass the VPN to avoid geoblocking/CAPTCHAs
var domesticDomains = []string{
	"gosuslugi.ru",
	"nalog.gov.ru",
	"mos.ru",
	"cbr.ru",
	"kremlin.ru",
	"sber.ru",
	"sberbank.ru",
	"tinkoff.ru",
	"tbank.ru",
	"vtb.ru",
	"alfabank.ru",
	"raiffeisen.ru",
	"gazprombank.ru",
	"nspk.ru",
	"mir-accept.ru",
	"yandex.ru",
	"ya.ru",
	"yandex.net",
	"vk.com",
	"vk.ru",
	"vk-cdn.net",
	"mail.ru",
	"ok.ru",
	"dzen.ru",
	"ozon.ru",
	"wildberries.ru",
	"avito.ru",
	"kinopoisk.ru",
	"2gis.ru",
	"hh.ru",
	"cian.ru",
	"rutube.ru",
}

// Foreign/censored domains that must always be routed through the tunnel
var censoredDomains = []string{
	"instagram.com",
	"facebook.com",
	"fbcdn.net",
	"twitter.com",
	"x.com",
	"twimg.com",
	"linkedin.com",
	"rutracker.org",
	"nnmclub.to",
	"meduza.io",
	"zona.media",
	"theins.ru",
	"bbc.com",
	"dw.com",
	"svoboda.org",
	"rferl.org",
	"torproject.org",
	"openai.com",
	"chatgpt.com",
	"claude.ai",
	"anthropic.com",
	"notion.so",
	"canva.com",
	"proton.me",
	"protonmail.com",
	"discord.com",
	"discordapp.com",
}

var privateSubnets []*net.IPNet

func init() {
	cidrs := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"::1/128",
		"fc00::/7",
		"fe80::/10",
	}
	for _, c := range cidrs {
		_, ipnet, err := net.ParseCIDR(c)
		if err == nil {
			privateSubnets = append(privateSubnets, ipnet)
		}
	}
}

// IsPrivateIP checks if the given IP address is in a LAN/private subnet
func IsPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, subnet := range privateSubnets {
		if subnet.Contains(ip) {
			return true
		}
	}
	return false
}

// DetermineRouting evaluates whether a destination should be routed DIRECT or through TUNNEL
func DetermineRouting(target string) RouteAction {
	target = strings.TrimSpace(strings.ToLower(target))

	// Strip port if present
	if host, _, err := net.SplitHostPort(target); err == nil {
		target = host
	}

	// 1. Check IP addresses
	if ip := net.ParseIP(target); ip != nil {
		if IsPrivateIP(target) {
			return ActionDirect
		}
		// Public IPs default to tunnel unless matched
		return ActionTunnel
	}

	// 2. Explicit censored domains take priority -> TUNNEL
	for _, cd := range censoredDomains {
		if target == cd || strings.HasSuffix(target, "."+cd) {
			return ActionTunnel
		}
	}

	// 3. Check explicit domestic services -> DIRECT
	for _, dd := range domesticDomains {
		if target == dd || strings.HasSuffix(target, "."+dd) {
			return ActionDirect
		}
	}

	// 4. Check Russian domestic TLDs -> DIRECT
	for _, tld := range russianTLDs {
		if strings.HasSuffix(target, tld) {
			return ActionDirect
		}
	}

	// 5. Default to TUNNEL for all foreign/global traffic
	return ActionTunnel
}

// GenerateSingBoxRouteRules returns the routing configuration for sing-box client engine
func GenerateSingBoxRouteRules() []map[string]interface{} {
	return []map[string]interface{}{
		{
			"type":        "logical",
			"mode":        "or",
			"rules": []map[string]interface{}{
				{"protocol": "dns"},
			},
			"outbound": "dns-out",
		},
		{
			"ip_is_private": true,
			"outbound":      "direct",
		},
		{
			"domain_suffix": censoredDomains,
			"outbound":      "proxy",
		},
		{
			"domain_suffix": domesticDomains,
			"outbound":      "direct",
		},
		{
			"domain_suffix": russianTLDs,
			"outbound":      "direct",
		},
		{
			"outbound": "proxy", // Default rule
		},
	}
}
