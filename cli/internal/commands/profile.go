package commands

import (
	"strings"

	"runpentests/cli/internal/config"
)

// cmdProfile manages the saved server profiles: one machine can talk to
// several servers, each with its own key, and one of them is current.
func cmdProfile(e *Env, args []string) int {
	if len(args) == 0 {
		return e.usage("profile needs a subcommand: list | use NAME | rm NAME [--yes]")
	}
	if wantsHelp(args) {
		return e.printCommandHelp("profile", nil)
	}
	switch args[0] {
	case "list":
		return profileList(e, args[1:])
	case "use":
		return profileUse(e, args[1:])
	case "rm":
		return profileRm(e, args[1:])
	}
	return e.usage("unknown profile subcommand %q", args[0])
}

// profileList prints NAME, SERVER and whether a key is set — never the key.
func profileList(e *Env, args []string) int {
	fs := e.newFlagSet("profile list")
	pos, err := parse(fs, args)
	if err != nil {
		return e.parseFailed("profile", fs, err)
	}
	if len(pos) > 0 {
		return e.usage("profile list takes no arguments")
	}
	path, err := e.configPath()
	if err != nil {
		return e.usage("%v", err)
	}
	st, err := config.ReadStore(path)
	if err != nil {
		return e.usage("%v", err)
	}
	names := st.Names()
	if len(names) == 0 {
		e.printf("no profiles saved\n")
		return ExitOK
	}
	e.printf("  %-24s  %-30s  %s\n", "NAME", "SERVER", "KEY")
	for _, name := range names {
		marker := " "
		if name == st.Current {
			marker = "*"
		}
		key := "none"
		if st.Profiles[name].APIKey != "" {
			key = "set"
		}
		e.printf("%s %-24s  %-30s  %s\n", marker, name, st.Profiles[name].Server, key)
	}
	return ExitOK
}

func profileUse(e *Env, args []string) int {
	fs := e.newFlagSet("profile use")
	pos, err := parse(fs, args)
	if err != nil {
		return e.parseFailed("profile", fs, err)
	}
	if len(pos) != 1 {
		return e.usage("profile use needs exactly one profile name")
	}
	path, err := e.configPath()
	if err != nil {
		return e.usage("%v", err)
	}
	st, err := config.ReadStore(path)
	if err != nil {
		return e.usage("%v", err)
	}
	name := pos[0]
	if _, ok := st.Profiles[name]; !ok {
		return e.usage("%v", config.UnknownProfileError(name, st))
	}
	st.Current = name
	if err := config.Save(path, st); err != nil {
		return e.usage("%v", err)
	}
	e.printf("using profile %s\n", name)
	return ExitOK
}

func profileRm(e *Env, args []string) int {
	fs := e.newFlagSet("profile rm")
	yes := fs.Bool("yes", false, "do not ask for confirmation")
	pos, err := parse(fs, args)
	if err != nil {
		return e.parseFailed("profile", fs, err)
	}
	if len(pos) != 1 {
		return e.usage("profile rm needs exactly one profile name")
	}
	path, err := e.configPath()
	if err != nil {
		return e.usage("%v", err)
	}
	st, err := config.ReadStore(path)
	if err != nil {
		return e.usage("%v", err)
	}
	name := pos[0]
	if _, ok := st.Profiles[name]; !ok {
		return e.usage("%v", config.UnknownProfileError(name, st))
	}
	// Removing a saved key is permanent: ask unless told not to, and never
	// guess in a pipe.
	if !*yes {
		if !e.IsTTY() {
			return e.usage("refusing to remove a profile without --yes (no terminal to confirm on)")
		}
		e.errorf("Remove profile %q? Type y to confirm: ", name)
		line, _ := e.readLine()
		if strings.ToLower(strings.TrimSpace(line)) != "y" {
			e.errorf("not removed\n")
			return ExitUsage
		}
	}
	wasCurrent := st.Current == name
	delete(st.Profiles, name)
	if wasCurrent {
		st.Current = ""
	}
	if len(st.Profiles) == 0 {
		if err := config.Clear(path); err != nil {
			return e.usage("%v", err)
		}
	} else if err := config.Save(path, st); err != nil {
		return e.usage("%v", err)
	}
	if wasCurrent {
		e.printf("removed profile %s; no profile is current now\n", name)
	} else {
		e.printf("removed profile %s\n", name)
	}
	return ExitOK
}
