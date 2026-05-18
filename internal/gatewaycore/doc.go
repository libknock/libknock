// Package gatewaycore contains shared gate and relay runtime helpers.
//
// It is internal because listener address normalization, firewall operation
// timeouts, event forwarding, and knock-listen address derivation are SDK
// implementation details. Public callers should configure gate or relay rather
// than depend on these low-level mechanics.
package gatewaycore
