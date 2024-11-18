package apiserver

type Config struct {
	BindAddr        string `toml:"bind_addr"`
	LogLevel        string `toml:"log_level"`
	DatabaseURL     string `toml:"database_url"`
	SessionKey      string `toml:"session_key"`
	SigningKey      string `toml:"singing_key"`
	Salt            string `toml:"salt"`
	TokenTTL        int64  `toml:"token_ttl"`
	RefreshTokenTTL int64  `toml:"refresh_token_ttl"`
}

func NewConfig() *Config {
	return &Config{
		BindAddr: ":8080",
		LogLevel: "debug",
	}
}
