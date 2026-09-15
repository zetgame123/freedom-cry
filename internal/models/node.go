package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type NodeRole string

const (
	RoleStandalone NodeRole = "standalone" // Single-hop: both entry and exit
	RoleEntry      NodeRole = "entry"      // Multi-hop: accepts client VPN connections, strictly forwards through fc-mesh0, NO direct internet WAN access
	RoleExit       NodeRole = "exit"       // Multi-hop: egress breakout to internet, accepts traffic strictly from Entry nodes over fc-mesh0
)

type ServerNode struct {
	ID          uuid.UUID  `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	Name        string     `gorm:"not null" json:"name"`
	Country     string     `gorm:"not null" json:"country"`
	CountryCode string     `gorm:"type:varchar(5);not null" json:"country_code"` // e.g. NL, DE, US
	Host        string     `gorm:"not null" json:"host"`                          // IP or domain
	IsOnline    bool       `gorm:"default:true" json:"is_online"`
	IsRevoked   bool       `gorm:"default:false" json:"is_revoked"`
	LoadPercent int        `gorm:"default:0" json:"load_percent"`
	LastSeenAt  *time.Time `json:"last_seen_at"`

	// --- Multi-Hop Topology & Mesh Configuration ---
	Role       NodeRole `gorm:"type:varchar(20);default:'standalone'" json:"role"`
	MeshIP     string   `gorm:"type:varchar(50)" json:"mesh_ip"`        // e.g. 10.99.1.1/24 (entry) or 10.99.2.1/24 (exit)
	MeshPort   int      `gorm:"default:51821" json:"mesh_port"`         // WireGuard inter-node mesh port
	MeshPubKey string   `gorm:"type:varchar(100)" json:"mesh_pub_key"` // WireGuard public key for inter-node mesh

	// --- Node Cryptographic Identity ---
	// Ed25519 public key of the node for mutual signature authentication
	PublicKey string `gorm:"type:varchar(128);index" json:"public_key"`
	// Unique per-node authentication token hash (SHA-256)
	AuthTokenHash string `gorm:"type:varchar(64);uniqueIndex" json:"-"`

	// Monotonic counter for concurrency-safe IP allocation
	LastAllocatedIP int `gorm:"default:1" json:"-"`

	// --- VLESS + Reality Configuration ---
	// NOTE: Server private key is generated and stored locally on the Node, NOT on Master.
	VlessEnabled      bool   `gorm:"default:true" json:"vless_enabled"`
	VlessPort         int    `gorm:"default:443" json:"vless_port"`
	RealityPubKey     string `gorm:"not null" json:"reality_pub_key"`                           // Server X25519 public key (pbk)
	RealityShortID    string `gorm:"not null" json:"reality_short_id"`                          // Short ID (hex)
	RealityServerName string `gorm:"not null;default:'dl.google.com'" json:"reality_server_name"`   // Current active SNI
	RealitySNIPool    string `gorm:"type:text;default:'www.microsoft.com,gateway.icloud.com,azure.microsoft.com,d1.awsstatic.com'" json:"reality_sni_pool"`

	// --- Hysteria 2 (QUIC + Brutal CC) Configuration ---
	HysteriaEnabled    bool   `gorm:"default:false" json:"hysteria_enabled"`
	HysteriaPort       int    `gorm:"default:8443" json:"hysteria_port"`
	HysteriaMasquerade string `gorm:"default:'https://bing.com'" json:"hysteria_masquerade"`

	// --- AmneziaWG (Obfuscated WireGuard) Configuration ---
	// NOTE: Server private key is generated and stored locally on the Node, NOT on Master.
	AwgEnabled      bool   `gorm:"default:true" json:"awg_enabled"`
	AwgPort         int    `gorm:"default:51820" json:"awg_port"`
	AwgServerSubnet string `gorm:"default:'10.8.0.1/16, fd00:8::1/64'" json:"awg_server_subnet"`
	AwgPubKey       string `gorm:"not null" json:"awg_pub_key"` // WireGuard public key
	// AWG Obfuscation Parameters
	AwgJc   int    `gorm:"default:4" json:"awg_jc"`      // Junk packet count
	AwgJmin int    `gorm:"default:50" json:"awg_jmin"`   // Junk min size
	AwgJmax int    `gorm:"default:1000" json:"awg_jmax"` // Junk max size
	AwgS1   int    `gorm:"default:64" json:"awg_s1"`     // Init padding size
	AwgS2   int    `gorm:"default:64" json:"awg_s2"`     // Response padding size
	AwgH1   uint32 `gorm:"not null" json:"awg_h1"`       // Init packet magic header
	AwgH2   uint32 `gorm:"not null" json:"awg_h2"`       // Response packet magic header
	AwgH3   uint32 `gorm:"not null" json:"awg_h3"`       // Underload packet magic header
	AwgH4   uint32 `gorm:"not null" json:"awg_h4"`       // Transport packet magic header

	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`
}

func (n *ServerNode) BeforeCreate(tx *gorm.DB) error {
	if n.ID == uuid.Nil {
		n.ID = uuid.New()
	}
	return nil
}
