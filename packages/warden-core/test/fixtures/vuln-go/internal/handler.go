package internal

import (
	"crypto/md5"
	"database/sql"
	"fmt"
	"os/exec"
)

func WeakHash(pw string) [16]byte { return md5.Sum([]byte(pw)) }

func FindUser(db *sql.DB, id string) *sql.Row {
	return db.QueryRow(fmt.Sprintf("SELECT * FROM users WHERE id = %s", id))
}

func RunReport(name string) error {
	return exec.Command("report " + name).Run()
}
