package handler

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"html/template"
	"net/http"
	"strings"

	"freedom-cry/internal/config"
	"freedom-cry/internal/models"
	"freedom-cry/internal/protocol/amneziawg"
	"freedom-cry/internal/protocol/xray"
	"freedom-cry/internal/service"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type ConfigHandler struct {
	subServ *service.SubscriptionService
	cfg     *config.Config
}

func NewConfigHandler(subServ *service.SubscriptionService, cfg *config.Config) *ConfigHandler {
	return &ConfigHandler{subServ: subServ, cfg: cfg}
}

// GetSubscription handles /sub/:token (Subscription link for V2RayN, Sing-box, Clash, Nekobox, Streisand)
func (h *ConfigHandler) GetSubscription(c *gin.Context) {
	token := c.Param("token")
	sub, err := h.subServ.GetByToken(token)
	if err != nil || !sub.IsValid() {
		c.Header("Referrer-Policy", "no-referrer")
		c.String(http.StatusForbidden, "Subscription expired, invalid or traffic limit reached")
		return
	}

	// Security headers
	c.Header("Referrer-Policy", "no-referrer")
	c.Header("X-Content-Type-Options", "nosniff")
	c.Header("Cache-Control", "no-store, no-cache, must-revalidate, private")

	// Standard Subscription-Userinfo header for modern clients
	userInfo := fmt.Sprintf("upload=0; download=%d; total=%d; expire=%d",
		sub.TrafficUsedBytes, sub.TrafficLimitBytes, sub.ExpiresAt.Unix())
	c.Header("Subscription-Userinfo", userInfo)
	c.Header("Profile-Update-Interval", "12") // hours

	var vlessLinks []string
	for _, key := range sub.ClientKeys {
		if key.Node.VlessEnabled && key.VlessUUID != "" && !key.Node.IsRevoked {
			link := xray.BuildVlessLink(
				key.VlessUUID,
				key.Node.Host,
				key.Node.VlessPort,
				key.Node.RealityPubKey,
				key.Node.RealityServerName,
				key.Node.RealityShortID,
				key.Node.Name,
			)
			vlessLinks = append(vlessLinks, link)
		}
	}

	// If requested by a web browser, render a secure HTML status page with contextual escaping
	accept := c.GetHeader("Accept")
	userAgent := strings.ToLower(c.GetHeader("User-Agent"))
	if strings.Contains(accept, "text/html") && !strings.Contains(userAgent, "v2ray") && !strings.Contains(userAgent, "clash") && !strings.Contains(userAgent, "sing-box") {
		h.renderHTMLPage(c, sub, vlessLinks)
		return
	}

	// Standard base64 subscription format for VPN clients
	joined := strings.Join(vlessLinks, "\n")
	encoded := base64.StdEncoding.EncodeToString([]byte(joined))

	c.Header("Content-Type", "text/plain; charset=utf-8")
	c.String(http.StatusOK, encoded)
}

// GetRawVless handles /sub/:token/vless (Plain text vless:// links)
func (h *ConfigHandler) GetRawVless(c *gin.Context) {
	token := c.Param("token")
	sub, err := h.subServ.GetByToken(token)
	if err != nil || !sub.IsValid() {
		c.Header("Referrer-Policy", "no-referrer")
		c.String(http.StatusForbidden, "Subscription invalid or expired")
		return
	}

	c.Header("Referrer-Policy", "no-referrer")
	c.Header("X-Content-Type-Options", "nosniff")
	c.Header("Cache-Control", "no-store, no-cache, must-revalidate, private")

	var vlessLinks []string
	for _, key := range sub.ClientKeys {
		if key.Node.VlessEnabled && key.VlessUUID != "" && !key.Node.IsRevoked {
			link := xray.BuildVlessLink(
				key.VlessUUID,
				key.Node.Host,
				key.Node.VlessPort,
				key.Node.RealityPubKey,
				key.Node.RealityServerName,
				key.Node.RealityShortID,
				key.Node.Name,
			)
			vlessLinks = append(vlessLinks, link)
		}
	}

	c.Header("Content-Type", "text/plain; charset=utf-8")
	c.String(http.StatusOK, strings.Join(vlessLinks, "\n"))
}

// GetAmneziaWGConfig handles /sub/:token/awg/:node_id (Downloads .conf template for AmneziaVPN / WireGuard)
func (h *ConfigHandler) GetAmneziaWGConfig(c *gin.Context) {
	token := c.Param("token")
	nodeIDStr := c.Param("node_id")

	nodeID, err := uuid.Parse(nodeIDStr)
	if err != nil {
		c.String(http.StatusBadRequest, "Invalid node ID")
		return
	}

	sub, err := h.subServ.GetByToken(token)
	if err != nil || !sub.IsValid() {
		c.String(http.StatusForbidden, "Subscription invalid or expired")
		return
	}

	c.Header("Referrer-Policy", "no-referrer")
	c.Header("X-Content-Type-Options", "nosniff")
	c.Header("Cache-Control", "no-store, no-cache, must-revalidate, private")

	var targetKey *models.ClientKey
	for _, k := range sub.ClientKeys {
		if k.NodeID == nodeID {
			targetKey = &k
			break
		}
	}

	if targetKey == nil || targetKey.Node.IsRevoked {
		c.String(http.StatusNotFound, "AmneziaWG node not found or inactive")
		return
	}

	// Zero Knowledge at Rest: Decrypt client private key using the secret bearer token
	clientPrivKey := "<INSERT_YOUR_LOCAL_CLIENT_PRIVATE_KEY_HERE>"
	if targetKey.AwgPrivateKeyEnc != "" {
		if decrypted, err := amneziawg.DecryptClientPrivateKey(token, targetKey.AwgPrivateKeyEnc); err == nil && decrypted != "" {
			clientPrivKey = decrypted
		}
	}

	confParams := amneziawg.ClientConfigParams{
		ClientPrivateKey: clientPrivKey,
		ClientAddress:    targetKey.AwgAddress,
		DNS:              h.cfg.App.DefaultDNS,
		Jc:               targetKey.Node.AwgJc,
		Jmin:             targetKey.Node.AwgJmin,
		Jmax:             targetKey.Node.AwgJmax,
		S1:               targetKey.Node.AwgS1,
		S2:               targetKey.Node.AwgS2,
		H1:               targetKey.Node.AwgH1,
		H2:               targetKey.Node.AwgH2,
		H3:               targetKey.Node.AwgH3,
		H4:               targetKey.Node.AwgH4,
		ServerPublicKey:  targetKey.Node.AwgPubKey,
		PresharedKey:     targetKey.AwgPresharedKey,
		Endpoint:         fmt.Sprintf("%s:%d", targetKey.Node.Host, targetKey.Node.AwgPort),
		AllowedIPs:       "0.0.0.0/0, ::/0",
	}

	confContent, err := amneziawg.GenerateClientConfig(confParams)
	if err != nil {
		c.String(http.StatusInternalServerError, "Failed to generate config")
		return
	}

	filename := fmt.Sprintf("FreedomCry-%s.conf", targetKey.Node.CountryCode)
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
	c.Header("Content-Type", "application/x-wireguard-profile")
	c.String(http.StatusOK, confContent)
}

// RegisterClientPubKey allows zero-trust clients to submit their own client-generated WireGuard public key
func (h *ConfigHandler) RegisterClientPubKey(c *gin.Context) {
	token := c.Param("token")
	nodeIDStr := c.Param("node_id")

	nodeID, err := uuid.Parse(nodeIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid node id"})
		return
	}

	sub, err := h.subServ.GetByToken(token)
	if err != nil || !sub.IsValid() {
		c.JSON(http.StatusNotFound, gin.H{"error": "subscription not found or inactive"})
		return
	}

	type PubKeyRequest struct {
		PublicKey string `json:"public_key" binding:"required"`
	}

	var req PubKeyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.subServ.UpdateClientAWGKey(sub.UserID, sub.ID, nodeID, req.PublicKey); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Custom client public key successfully registered for AmneziaWG node",
	})
}

// GetSubInfo handles /sub/:token/info (JSON metadata)
func (h *ConfigHandler) GetSubInfo(c *gin.Context) {
	token := c.Param("token")
	sub, err := h.subServ.GetByToken(token)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "subscription not found"})
		return
	}

	c.Header("Referrer-Policy", "no-referrer")
	c.Header("X-Content-Type-Options", "nosniff")
	c.Header("Cache-Control", "no-store, no-cache, must-revalidate, private")

	type NodeLinkInfo struct {
		NodeID     uuid.UUID `json:"node_id"`
		NodeName   string    `json:"node_name"`
		Country    string    `json:"country"`
		VlessLink  string    `json:"vless_link"`
		AwgConfURL string    `json:"awg_conf_url"`
	}

	var nodes []NodeLinkInfo
	for _, k := range sub.ClientKeys {
		if k.Node.IsRevoked {
			continue
		}
		vless := ""
		if k.Node.VlessEnabled && k.VlessUUID != "" {
			vless = xray.BuildVlessLink(
				k.VlessUUID,
				k.Node.Host,
				k.Node.VlessPort,
				k.Node.RealityPubKey,
				k.Node.RealityServerName,
				k.Node.RealityShortID,
				k.Node.Name,
			)
		}
		awgURL := fmt.Sprintf("%s/sub/%s/awg/%s", h.cfg.App.BaseURL, sub.Token, k.NodeID)

		nodes = append(nodes, NodeLinkInfo{
			NodeID:     k.NodeID,
			NodeName:   k.Node.Name,
			Country:    k.Node.Country,
			VlessLink:  vless,
			AwgConfURL: awgURL,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"subscription_id":     sub.ID,
		"status":              sub.Status,
		"plan_name":           sub.Plan.Name,
		"expires_at":          sub.ExpiresAt,
		"traffic_limit_bytes": sub.TrafficLimitBytes,
		"traffic_used_bytes":  sub.TrafficUsedBytes,
		"nodes":               nodes,
	})
}

type htmlPageData struct {
	PlanName        string
	Status          string
	ExpiresAt       string
	SubscriptionURL string
	Nodes           []htmlNodeData
}

type htmlNodeData struct {
	Name       string
	Country    string
	VlessLink  string
	AwgConfURL string
}

const subscriptionTemplateHTML = `<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="referrer" content="no-referrer">
    <title>Freedom Cry VPN - Подписка</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 20px; }
        .container { max-width: 700px; margin: 0 auto; background: #1e293b; padding: 30px; border-radius: 12px; box-shadow: 0 10px 30px rgba(0,0,0,0.5); }
        h1 { color: #38bdf8; margin-top: 0; }
        .badge { display: inline-block; padding: 4px 10px; border-radius: 6px; font-weight: bold; background: #22c55e; color: #000; }
        .section { margin-top: 25px; border-top: 1px solid #334155; padding-top: 20px; }
        .code-box { background: #0b0f19; padding: 12px; border-radius: 6px; font-family: monospace; font-size: 13px; word-break: break-all; margin: 10px 0; border: 1px solid #334155; }
        a.button { display: inline-block; background: #38bdf8; color: #0f172a; padding: 10px 18px; border-radius: 6px; text-decoration: none; font-weight: bold; margin-top: 8px; }
        a.button:hover { background: #7dd3fc; }
        .node-card { background: #0f172a; padding: 15px; border-radius: 8px; margin-bottom: 15px; border: 1px solid #334155; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🦅 Freedom Cry VPN</h1>
        <p>Тариф: <strong>{{.PlanName}}</strong> <span class="badge">{{.Status}}</span></p>
        <p>Истекает: <strong>{{.ExpiresAt}}</strong></p>

        <div class="section">
            <h3>🔗 Ссылка для автоматической подписки</h3>
            <p>Вставьте эту ссылку в приложения (v2rayN, Sing-box, Clash Verge, NekoBox, Streisand):</p>
            <div class="code-box">{{.SubscriptionURL}}</div>
        </div>

        <div class="section">
            <h3>⚡ Доступные серверы и протоколы</h3>
            {{range .Nodes}}
            <div class="node-card">
                <h4>🌍 {{.Name}} ({{.Country}})</h4>
                {{if .VlessLink}}
                <p><strong>VLESS + Reality (Xray):</strong></p>
                <div class="code-box">{{.VlessLink}}</div>
                {{end}}
                {{if .AwgConfURL}}
                <p><strong>AmneziaWG (Анти-ТСПУ):</strong></p>
                <a class="button" href="{{.AwgConfURL}}">Скачать .conf для AmneziaVPN</a>
                {{end}}
            </div>
            {{end}}
        </div>
    </div>
</body>
</html>`

var parsedSubTemplate = template.Must(template.New("subscriptionPage").Parse(subscriptionTemplateHTML))

func (h *ConfigHandler) renderHTMLPage(c *gin.Context, sub *models.Subscription, vlessLinks []string) {
	// Strict Content Security Policy and privacy headers
	c.Header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; font-src 'self'; script-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none';")
	c.Header("Referrer-Policy", "no-referrer")
	c.Header("X-Content-Type-Options", "nosniff")
	c.Header("X-Frame-Options", "DENY")
	c.Header("Cache-Control", "no-store, no-cache, must-revalidate, private")

	data := htmlPageData{
		PlanName:        sub.Plan.Name,
		Status:          string(sub.Status),
		ExpiresAt:       sub.ExpiresAt.Format("02.01.2006 15:04"),
		SubscriptionURL: fmt.Sprintf("%s/sub/%s", h.cfg.App.BaseURL, sub.Token),
	}

	for _, k := range sub.ClientKeys {
		if k.Node.IsRevoked {
			continue
		}
		vless := ""
		if k.Node.VlessEnabled && k.VlessUUID != "" {
			vless = xray.BuildVlessLink(
				k.VlessUUID,
				k.Node.Host,
				k.Node.VlessPort,
				k.Node.RealityPubKey,
				k.Node.RealityServerName,
				k.Node.RealityShortID,
				k.Node.Name,
			)
		}
		awgURL := fmt.Sprintf("%s/sub/%s/awg/%s", h.cfg.App.BaseURL, sub.Token, k.NodeID)

		data.Nodes = append(data.Nodes, htmlNodeData{
			Name:       k.Node.Name,
			Country:    k.Node.Country,
			VlessLink:  vless,
			AwgConfURL: awgURL,
		})
	}

	var buf bytes.Buffer
	if err := parsedSubTemplate.Execute(&buf, data); err != nil {
		c.String(http.StatusInternalServerError, "Error rendering page")
		return
	}

	c.Header("Content-Type", "text/html; charset=utf-8")
	c.String(http.StatusOK, buf.String())
}
