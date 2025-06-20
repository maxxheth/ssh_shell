package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/maxxheth/ssh_shell/internal/auth"
	"github.com/maxxheth/ssh_shell/internal/hostkey"
	"github.com/maxxheth/ssh_shell/internal/script"
	"github.com/maxxheth/ssh_shell/internal/session"
)

// main is the entry point of the application.
// It parses command-line flags, sets up the SSH connection, and
// either executes a remote script or starts an interactive shell.
func main() {
	// Capture the current working directory immediately to support relative paths
	cwd, err := os.Getwd()
	if err != nil {
		log.Fatalf("Failed to get current working directory: %v", err)
	}

	// 1. Define and parse command-line flags for connection details.
	user := flag.String("user", os.Getenv("USER"), "SSH username (defaults to current user)")
	host := flag.String("host", "", "Remote server host or IP address")
	port := flag.Int("port", 22, "Remote server port")
	scriptPath := flag.String("script", "", "Path to a local script to execute on the remote server")
	scriptFlags := flag.String("script-flags", "", "A string of flags to pass to the remote script (e.g., \"--backup-dir /tmp --dry-run\")")
	usePython := flag.Bool("py", false, "Execute script using Python instead of bash")
	keyPath := flag.String("key", filepath.Join(os.Getenv("HOME"), ".ssh", "id_rsa"), "Path to your SSH private key")
	authViaEnv := flag.Bool("auth-via-env", false, "Use SSH_KEY_PASSPHRASE environment variable for authentication")
	useAgent := flag.Bool("use-agent", true, "Use ssh-agent for authentication (default: true)")
	askForPassphrase := flag.Bool("ask-for-passphrase", false, "Prompt for passphrase if key is encrypted and other methods fail")
	knownHostsPath := flag.String("known-hosts", "", "Path to known_hosts file (defaults to ~/.ssh/known_hosts)")
	insecureHostKey := flag.Bool("insecure-host-key", false, "Skip host key verification (INSECURE - only for development)")
	flag.Parse()

	// Ensure cached passphrase is cleared when program exits
	defer auth.ClearCachedPassphrase()

	// Resolve script path relative to the original working directory
	if *scriptPath != "" && !filepath.IsAbs(*scriptPath) {
		*scriptPath = filepath.Join(cwd, *scriptPath)
	}

	// Validate that the host is provided.
	if *host == "" {
		log.Println("Error: a remote host must be specified with the -host flag.")
		flag.Usage()
		os.Exit(1)
	}

	// 2. Prepare the SSH client configuration.
	// This includes authentication methods and host key verification.
	authMethods, err := auth.GetAuthMethods(*keyPath, *authViaEnv, *useAgent, *askForPassphrase)
	if err != nil {
		log.Fatalf("Failed to setup authentication: %v", err)
	}

	// Configure host key verification
	var hostKeyCallback ssh.HostKeyCallback
	if *insecureHostKey {
		log.Println("WARNING: Host key verification disabled. This is insecure and should only be used for development.")
		hostKeyCallback = hostkey.InsecureIgnoreHostKey()
	} else {
		log.Println("Using secure host key verification with known_hosts file.")
		hostKeyCallback = hostkey.VerifyHostKey(*knownHostsPath)
	}

	sshConfig := &ssh.ClientConfig{
		User:            *user,
		Auth:            authMethods,
		HostKeyCallback: hostKeyCallback,
		Timeout:         5 * time.Second,
	}

	// 3. Establish the SSH connection.
	serverAddr := fmt.Sprintf("%s:%d", *host, *port)
	log.Printf("Connecting to %s...", serverAddr)
	client, err := ssh.Dial("tcp", serverAddr, sshConfig)
	if err != nil {
		log.Fatalf("Failed to dial: %v", err)
	}
	defer client.Close()
	log.Println("Connection successful.")

	// 4. Decide whether to run a script or start an interactive shell.
	if *scriptPath != "" {
		// Mode 1: Execute a remote script
		script.ExecuteScript(client, *scriptPath, *scriptFlags, *usePython)
	} else {
		// Mode 2: Start an interactive shell
		session.StartInteractiveShell(client)
	}
}
