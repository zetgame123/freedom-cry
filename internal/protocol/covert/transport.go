package covert

import (
	"context"
	"time"
)

type Transport interface {
	Name() string
	Start(ctx context.Context) error
	Stop() error
	Send(data []byte) error
	OnReceive(handler func([]byte))
	IsConnected() bool
	Stats() TransportStats
}

type TransportStats struct {
	BytesSent     uint64        `json:"bytes_sent"`
	BytesReceived uint64        `json:"bytes_received"`
	PacketsSent   uint64        `json:"packets_sent"`
	PacketsRecv   uint64        `json:"packets_recv"`
	Connected     bool          `json:"connected"`
	Uptime        time.Duration `json:"uptime"`
}
