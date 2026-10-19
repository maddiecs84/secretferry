package app

import "time"

// httpTimeout bounds each request to the Cloudflare API.
const httpTimeout = 30 * time.Second
