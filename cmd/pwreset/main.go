// Command pwreset is the offline password recovery path: it rewrites one user's
// scrypt password straight in a PostLite database, for when nobody remembers the
// admin password and there is no way in through the UI.
//
//	go run ./cmd/pwreset -data ./data -user admin          # random password, printed once
//	go run ./cmd/pwreset -data ./data -list                # who is in this database
//
// It reuses the pieces the admin reset-password endpoint uses
// (auth.HashPassword -> repository.Users.SetPassword), so the row it writes is
// indistinguishable from one written by the app, and it records the same audit
// line. Two things are worth knowing:
//
//   - It may run while the server is up: SQLite is in WAL mode, so a concurrent
//     write is safe, and the server reads users from the database on every login,
//     which means the new password works immediately.
//   - Like the HTTP endpoint it does not revoke existing sessions: sign out
//     anywhere still logged in as that user.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"postlite/internal/auth"
	"postlite/internal/db"
	"postlite/internal/repository"
)

// auditLimit matches the cap the server keeps in settings.audit_log.
const auditLimit = 500

func main() {
	dataDir := flag.String("data", "./data", "PostLite data directory (holds postlite.db, master.key, certs)")
	user := flag.String("user", "admin", "username whose password to reset")
	password := flag.String("password", "", "new password (empty: generate a random one; note that a password passed here lands in your shell history)")
	list := flag.Bool("list", false, "list the users in the database and exit")
	flag.Usage = usage
	flag.Parse()

	if _, err := os.Stat(filepath.Join(*dataDir, "postlite.db")); err != nil {
		fmt.Fprintf(os.Stderr,
			"warning: %s has no database yet, so there is nothing to reset there\n", *dataDir)
	}
	sdb, err := db.Open(*dataDir)
	if err != nil {
		die("open %s: %v", *dataDir, err)
	}
	defer sdb.Close()
	store := repository.New(sdb)

	if *list {
		users, err := store.Users.List()
		if err != nil {
			die("list users: %v", err)
		}
		if len(users) == 0 {
			fmt.Printf("%s holds no database yet: start the server once to initialise it\n", *dataDir)
			return
		}
		for _, u := range users {
			state := "enabled"
			if !u.Enabled {
				state = "disabled"
			}
			fmt.Printf("%d\t%s\t%s\t%s\n", u.ID, u.Username, u.Role, state)
		}
		return
	}

	u, err := store.Users.GetByUsername(*user)
	if err != nil {
		die("user %q: %v (try -list)", *user, err)
	}
	if !u.Enabled {
		fmt.Fprintf(os.Stderr,
			"warning: %q is disabled, the new password will not work until it is enabled again\n", u.Username)
	}

	newPass := *password
	if newPass == "" {
		newPass, err = auth.RandomPassword(16)
		if err != nil {
			die("generate password: %v", err)
		}
	}
	if len(newPass) < 6 {
		die("password too short (the UI enforces at least 6 characters)")
	}

	hash, salt, err := auth.HashPassword(newPass)
	if err != nil {
		die("hash password: %v", err)
	}
	if err := store.Users.SetPassword(u.ID, salt, hash); err != nil {
		die("set password: %v", err)
	}

	// Same audit trail as an admin doing it from the Users view, so the reset is
	// visible there instead of only in someone's terminal scrollback.
	if err := store.Settings.AppendAudit(auth.AuditLine("cli", "user.reset_password", "id="+strconv.FormatInt(u.ID, 10)), auditLimit); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not record the audit line: %v\n", err)
	}

	// Best effort: fold the change into the main database file so that it does not
	// depend on a later crash-recovery of the write-ahead log. TRUNCATE is a no-op
	// while a server holds the database; then the commit simply lives in the WAL,
	// which SQLite replays on the next open.
	var busy, logPages, checkpointed int
	if err := sdb.QueryRow("PRAGMA wal_checkpoint(TRUNCATE)").Scan(&busy, &logPages, &checkpointed); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not checkpoint the WAL: %v\n", err)
	}

	fmt.Printf("reset password for %q (id=%d, %s) in %s\n", u.Username, u.ID, u.Role, *dataDir)
	fmt.Printf("new password: %s\n", newPass)
	fmt.Println("sign in, then change it (Users -> Reset password). Existing sessions are not revoked.")
}

func usage() {
	fmt.Fprintf(os.Stderr, `usage: pwreset [flags]

Offline password recovery for a PostLite data directory. Run it where the server
runs, against the same -data directory.

flags:
`)
	flag.PrintDefaults()
	fmt.Fprintf(os.Stderr, `
examples:
  pwreset -data ./data -list                        list users
  pwreset -data ./data -user admin                  reset admin, print a random password
  pwreset -data ./data -user admin -password secret set it to a known value
`)
}

func die(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "pwreset: "+format+"\n", args...)
	os.Exit(1)
}
