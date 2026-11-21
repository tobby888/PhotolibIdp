package main

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/joho/godotenv"
)

type config struct {
	listenAddr       string
	publicOrigin     string
	stateDir         string
	adminUsername    string
	adminDisplayName string
	adminPassword    string
	adminEmail       string
	values           map[string]string
}

func loadConfig(path string) (config, error) {
	values, err := godotenv.Read(path)
	if err != nil {
		return config{}, fmt.Errorf("cannot read or parse %s", path)
	}
	return parseConfig(values)
}

func parseConfig(values map[string]string) (config, error) {
	origin, err := httpsOrigin(strings.Trim(values["IDP_PUBLIC_URL"], `'" `))
	if err != nil {
		return config{}, errors.New("IDP_PUBLIC_URL must be an HTTPS origin")
	}
	addr := strings.TrimSpace(values["IDP_LISTEN_ADDR"])
	if addr == "" {
		addr = "127.0.0.1:8090"
	}
	stateDir := strings.TrimSpace(values["IDP_STATE_DIR"])
	if stateDir == "" {
		stateDir = os.Getenv("STATE_DIRECTORY")
	}
	if stateDir == "" {
		stateDir = "data"
	}
	adminUser := strings.TrimSpace(values["IDP_ADMIN_USERNAME"])
	if adminUser == "" {
		adminUser = "admin"
	}
	adminName := strings.TrimSpace(values["IDP_ADMIN_DISPLAY_NAME"])
	if adminName == "" {
		adminName = "系统管理员"
	}
	return config{
		listenAddr:       addr,
		publicOrigin:     origin,
		stateDir:         stateDir,
		adminUsername:    adminUser,
		adminDisplayName: adminName,
		adminPassword:    strings.Trim(values["IDP_ADMIN_PASSWORD"], `'"`),
		adminEmail:       strings.TrimSpace(values["IDP_ADMIN_EMAIL"]),
		values:           values,
	}, nil
}

func httpsOrigin(value string) (string, error) {
	u, err := url.Parse(value)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil ||
		(u.Path != "" && u.Path != "/") || u.ForceQuery || u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("invalid HTTPS origin")
	}
	host := strings.ToLower(u.Host)
	if u.Port() == "443" {
		host = strings.TrimSuffix(host, ":443")
	}
	return "https://" + host, nil
}

func validateRedirectURI(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return "", errors.New("回调 URL 必须是有效的完整地址，且不能包含 # 片段")
	}
	host := strings.ToLower(u.Hostname())
	isLocal := host == "localhost" || host == "127.0.0.1"
	if u.Scheme != "https" && !(u.Scheme == "http" && isLocal) {
		return "", errors.New("回调 URL 必须使用 HTTPS（本地调试 localhost 除外）")
	}
	if u.Scheme == "https" && u.Port() == "443" {
		u.Host = strings.TrimSuffix(strings.ToLower(u.Host), ":443")
	} else {
		u.Host = strings.ToLower(u.Host)
	}
	if u.Path == "" {
		u.Path = "/"
	}
	return u.String(), nil
}
