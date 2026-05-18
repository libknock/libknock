package gatewaycore

func DefaultString(v, fallback string) string {
	if v != "" {
		return v
	}
	return fallback
}
