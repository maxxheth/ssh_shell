package script

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
)

// ExecuteScript reads a local script file and executes it on the remote server,
// passing along any provided script flags. It supports both bash and Python execution.
func ExecuteScript(client *ssh.Client, scriptPath string, scriptFlags string, usePython bool) {
	log.Printf("Executing script: %s", scriptPath)
	if scriptFlags != "" {
		log.Printf("With script flags: %s", scriptFlags)
	}

	// Read the script file content.
	scriptBytes, err := os.ReadFile(scriptPath)
	if err != nil {
		log.Fatalf("Failed to read script file '%s': %v", scriptPath, err)
	}

	// Create a new session for this command.
	session, err := client.NewSession()
	if err != nil {
		log.Fatalf("Failed to create session: %v", err)
	}
	defer session.Close()

	// Pipe the script content to the session's standard input.
	session.Stdin = bytes.NewReader(scriptBytes)
	// Connect the session's standard output and error to the local terminal.
	session.Stdout = os.Stdout
	session.Stderr = os.Stderr

	// Construct the remote command based on the interpreter type.
	var command string
	if usePython {
		// For Python scripts, use "python3 -" to read from stdin
		// The "-" tells Python to read the script from stdin
		if scriptFlags != "" {
			// For Python, we need to pass arguments differently since Python doesn't
			// support the same argument parsing as bash. We'll use sys.argv approach.
			command = fmt.Sprintf("python3 - %s", strings.TrimSpace(scriptFlags))
		} else {
			command = "python3 -"
		}
		log.Printf("Executing Python script with command: %s", command)
	} else {
		// Default bash execution
		// "bash -s" tells bash to read the script from stdin.
		// The "--" is crucial; it signifies the end of options for bash itself,
		// ensuring that everything in `scriptFlags` is passed as arguments to the script.
		if scriptFlags != "" {
			command = fmt.Sprintf("bash -s -- %s", strings.TrimSpace(scriptFlags))
		} else {
			command = "bash -s"
		}
		log.Printf("Executing bash script with command: %s", command)
	}

	if err := session.Run(command); err != nil {
		log.Fatalf("Failed to run script with command '%s': %v", command, err)
	}
	log.Println("Script execution finished.")
}
