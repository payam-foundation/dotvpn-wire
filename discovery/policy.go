package discovery

// ServerListPolicy selects which endpoints belong in a signed list.
type ServerListPolicy string

const (
	// PolicyBootstrap is the public clear channel: live system + public
	// reverse relays only (no bare node IPs).
	PolicyBootstrap ServerListPolicy = "bootstrap"
	// PolicyFleet is the encrypted full inventory: nodes + static + eligible
	// relays for the account.
	PolicyFleet ServerListPolicy = "fleet"
)
