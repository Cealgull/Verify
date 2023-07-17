package config

type VerifyConfig struct {
	Email struct {
		Dialer struct {
			Host    string `yaml:"host"`
			Port    int    `yaml:"port"`
			From    string `yaml:"from"`
			Todom   string `yaml:"todom"`
			Secret  string `yaml:"secret"`
			Subject string `yaml:"subject"`
		} `yaml:"dialer"`
		Redis struct {
			Host   string `yaml:"host"`
			Port   int    `yaml:"port"`
			User   string `yaml:"user"`
			Secret string `yaml:"string"`
			DB     int    `yaml:"db"`
		} `yaml:"redis"`
		Template string `yaml:"template"`
		Accrule  string `yaml:"accrule"`
		Coderule string `yaml:"coderule"`
	} `yaml:"email"`
	Cert struct {
		Priv string `yaml:"priv"`
		Cert string `yaml:"cert"`
	} `yaml:"cert"`
	Keyset struct {
		NR_mem int `yaml:"nr_mem"`
		Cap    int `yaml:"cap"`
	} `yaml:"keyset"`
	Turnstile struct {
		Secret string `yaml:"secret"`
	} `yaml:"turnstile"`
	Verify struct {
		Host string `yaml:"host"`
		Port int    `yaml:"port"`
	} `yaml:"verify"`
}
