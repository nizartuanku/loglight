package logingest

import (
	"bufio"
	"context"
	"os/exec"
	"time"
)

// CommandSource runs a follow-style command and emits one Event per stdout line.
// journald and Docker readers are thin wrappers over this: on a Linux host the
// simplest robust reader is the platform's own follow command, which handles
// cursors/rotation for us. If the command isn't available, Run returns its error
// and the engine simply reports the source as down — it never blocks the others.
type CommandSource struct {
	SourceID string
	Kind     SourceType
	Host     string
	App      string
	Name     string   // executable
	Args     []string // arguments

	// Now is the clock used as the fallback timestamp for lines that carry no
	// parseable header. Tests override it; production leaves it nil.
	Now func() time.Time
}

func (c *CommandSource) ID() string       { return c.SourceID }
func (c *CommandSource) Type() SourceType { return c.Kind }

func (c *CommandSource) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *CommandSource) Run(ctx context.Context, emit func(Event)) error {
	cmd := exec.CommandContext(ctx, c.Name, c.Args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		return err
	}
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		if ctx.Err() != nil {
			break
		}
		emit(ParseLine(c.Kind, c.SourceID, c.Host, c.App, sc.Text(), c.now()))
	}
	return cmd.Wait()
}

// NewJournaldSource follows the systemd journal in plain-message form. An
// optional unit filter narrows it (e.g. "sshd.service").
func NewJournaldSource(id, unit string) *CommandSource {
	args := []string{"-f", "-o", "cat", "--no-pager"}
	if unit != "" {
		args = append(args, "-u", unit)
	}
	return &CommandSource{SourceID: id, Kind: SourceJournald, Name: "journalctl", Args: args}
}

// NewDockerSource follows a container's logs. Container is the name or id.
func NewDockerSource(id, container string) *CommandSource {
	return &CommandSource{
		SourceID: id, Kind: SourceDocker, App: container,
		Name: "docker", Args: []string{"logs", "-f", "--since", "0m", container},
	}
}

// verify CommandSource satisfies Source at compile time.
var _ Source = (*CommandSource)(nil)
var _ = time.Second
