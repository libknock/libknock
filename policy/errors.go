package policy

import "errors"

var (
	ErrRateLimited = errors.New("rate limited")
	ErrBanListFull = errors.New("ban list full")
)
