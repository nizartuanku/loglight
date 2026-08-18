package loglight

import (
	"fmt"

	"github.com/nizartuanku/loglight/logingest"
)

// validateSource checks a source type and its required params.
func validateSource(typ string, params map[string]string) error {
	switch typ {
	case "syslog", "windows":
		if params["udp"] == "" && params["tcp"] == "" {
			return fmt.Errorf("a %s source needs a udp and/or tcp listen address (e.g. 0.0.0.0:5514)", typ)
		}
	case "file":
		if params["path"] == "" {
			return fmt.Errorf("a file source needs a path")
		}
	case "docker":
		if params["container"] == "" {
			return fmt.Errorf("a docker source needs a container name or id")
		}
	case "journald":
		// unit is optional (whole journal if empty)
	default:
		return fmt.Errorf("unknown source type %q", typ)
	}
	return nil
}

// BuildSource turns a stored SourceConfig into a runnable logingest.Source. The
// cmd calls this to start ingesting when a source is added or restored.
func BuildSource(s SourceConfig) (logingest.Source, error) {
	if err := validateSource(s.Type, s.Params); err != nil {
		return nil, err
	}
	switch s.Type {
	case "syslog":
		return &logingest.SyslogSource{SourceID: s.Name, UDPAddr: s.Params["udp"], TCPAddr: s.Params["tcp"],
			Kind: logingest.SourceSyslog}, nil
	case "windows":
		return &logingest.SyslogSource{SourceID: s.Name, UDPAddr: s.Params["udp"], TCPAddr: s.Params["tcp"],
			Kind: logingest.SourceWindows}, nil
	case "file":
		return &logingest.FileSource{SourceID: s.Name, Path: s.Params["path"],
			Host: s.Params["host"], App: s.Params["app"]}, nil
	case "journald":
		return logingest.NewJournaldSource(s.Name, s.Params["unit"]), nil
	case "docker":
		return logingest.NewDockerSource(s.Name, s.Params["container"]), nil
	}
	return nil, fmt.Errorf("unknown source type %q", s.Type)
}
