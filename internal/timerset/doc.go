// Package timerset tracks timers owned by gate and relay lifecycles.
//
// It exists to make shutdown deterministic: runtime code can register TTL work
// and stop all pending callbacks when listeners or gateways close.
package timerset
