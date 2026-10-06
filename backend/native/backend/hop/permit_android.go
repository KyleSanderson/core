//go:build android

package hop

// No-op on Android (uses protect)
func PermitUnderlayPeers(_ string) {}
