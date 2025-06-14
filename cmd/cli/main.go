package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/term"
)

// Global variable to cache the passphrase
var cachedPassphrase []byte

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
	keyPath := flag.String("key", filepath.Join(os.Getenv("HOME"), ".ssh", "id_rsa"), "Path to your SSH private key")
	authViaEnv := flag.Bool("auth-via-env", false, "Use SSH_KEY_PASSPHRASE environment variable for authentication")
	useAgent := flag.Bool("use-agent", true, "Use ssh-agent for authentication (default: true)")
	askForPassphrase := flag.Bool("ask-for-passphrase", false, "Prompt for passphrase if key is encrypted and other methods fail")
	flag.Parse()

	// Ensure cached passphrase is cleared when program exits
	defer clearCachedPassphrase()

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
	authMethods, err := getAuthMethods(*keyPath, *authViaEnv, *useAgent, *askForPassphrase)
	if err != nil {
		log.Fatalf("Failed to setup authentication: %v", err)
	}

	sshConfig := &ssh.ClientConfig{
		User: *user,
		Auth: authMethods,
		// IMPORTANT: In a production environment, you should use a more secure
		// HostKeyCallback, like one that checks against a known_hosts file.
		// ssh.InsecureIgnoreHostKey() is used here for convenience.
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
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
		executeScript(client, *scriptPath, *scriptFlags)
	} else {
		// Mode 2: Start an interactive shell
		startInteractiveShell(client)
	}
}

// executeScript reads a local script file and executes it on the remote server,
// passing along any provided script flags.
func executeScript(client *ssh.Client, scriptPath string, scriptFlags string) {
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

	// Construct the remote command. "bash -s" tells bash to read the script from stdin.
	// The "--" is crucial; it signifies the end of options for bash itself,
	// ensuring that everything in `scriptFlags` is passed as arguments to the script.
	var command string
	if scriptFlags != "" {
		// Properly handle the script flags - trim whitespace and ensure proper spacing
		command = fmt.Sprintf("bash -s -- %s", strings.TrimSpace(scriptFlags))
	} else {
		command = "bash -s"
	}

	log.Printf("Executing command: %s", command)
	if err := session.Run(command); err != nil {
		log.Fatalf("Failed to run script with command '%s': %v", command, err)
	}
	log.Println("Script execution finished.")
}

// startInteractiveShell opens a fully interactive PTY shell on the remote server.
func startInteractiveShell(client *ssh.Client) {
	log.Println("Starting interactive shell...")
	session, err := client.NewSession()
	if err != nil {
		log.Fatalf("Failed to create session: %v", err)
	}
	defer session.Close()

	// Set up the local terminal.
	// We need to get the file descriptor for stdin and put the terminal into "raw mode".
	// Raw mode allows us to pass all keystrokes (like Ctrl+C) directly to the remote shell.
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		log.Fatal("Standard input is not a terminal, cannot start interactive shell.")
	}

	oldState, err := term.MakeRaw(fd)
	if err != nil {
		log.Fatalf("Failed to put terminal into raw mode: %v", err)
	}
	// VERY IMPORTANT: Ensure the terminal state is restored on exit.
	defer term.Restore(fd, oldState)

	// Connect the local terminal's stdin, stdout, and stderr to the remote session.
	session.Stdout = os.Stdout
	session.Stderr = os.Stderr
	session.Stdin = os.Stdin

	// Get the terminal dimensions.
	width, height, err := term.GetSize(fd)
	if err != nil {
		log.Fatalf("Failed to get terminal size: %v", err)
	}

	// Request a pseudo-terminal (PTY) from the remote server.
	// The terminal type "xterm-256color" is a common and safe choice.
	if err := session.RequestPty("xterm-256color", height, width, ssh.TerminalModes{}); err != nil {
		log.Fatalf("Failed to request PTY: %v", err)
	}

	// Start a shell on the remote server.
	if err := session.Shell(); err != nil {
		log.Fatalf("Failed to start shell: %v", err)
	}

	// Handle window resize events.
	// This goroutine listens for SIGWINCH signals and updates the remote PTY size accordingly.
	go monitorWindowSize(session, fd)

	// Wait for the remote session to complete. This blocks until the user exits the remote shell.
	session.Wait()
	log.Println("Shell session finished.")
}

// monitorWindowSize listens for terminal resize signals (SIGWINCH) and
// informs the remote SSH session about the new dimensions.
func monitorWindowSize(session *ssh.Session, fd int) {
	sigwinch := make(chan os.Signal, 1)
	signal.Notify(sigwinch, syscall.SIGWINCH)
	defer signal.Stop(sigwinch)

	for {
		// Wait for a signal. If the channel is closed, exit the loop.
		s, ok := <-sigwinch
		if !ok || s == nil {
			return
		}

		width, height, err := term.GetSize(fd)
		if err != nil {
			log.Printf("Error getting terminal size: %v", err)
			continue
		}

		// Inform the remote session of the window size change.
		err = session.WindowChange(height, width)
		if err != nil {
			// If the session is closed, this will error out, which is fine.
			// We can stop monitoring at this point.
			break
		}
	}
}

// getAuthMethods returns a slice of authentication methods, prioritizing ssh-agent if available
func getAuthMethods(keyPath string, authViaEnv bool, useAgent bool, askForPassphrase bool) ([]ssh.AuthMethod, error) {
	var authMethods []ssh.AuthMethod

	// Try ssh-agent first if enabled
	if useAgent {
		if agentAuth := getAgentAuth(); agentAuth != nil {
			log.Println("Using ssh-agent for authentication")
			authMethods = append(authMethods, agentAuth)
			// If ssh-agent is working, we can return early and skip file-based auth
			return authMethods, nil
		} else {
			log.Println("ssh-agent not available or no keys loaded")
			log.Println("Hint: Run 'ssh-add ~/.ssh/id_rsa' to add your key to ssh-agent")
		}
	}

	// Fallback to key file authentication only if ssh-agent failed
	log.Println("Falling back to key file authentication")
	keyAuth, err := getKeyAuth(keyPath, authViaEnv, askForPassphrase)
	if err != nil {
		return nil, fmt.Errorf("failed to setup key file authentication: %v", err)
	}

	if keyAuth != nil {
		authMethods = append(authMethods, keyAuth)
	}

	if len(authMethods) == 0 {
		return nil, fmt.Errorf("no authentication methods available - try using ssh-agent or the -ask-for-passphrase flag")
	}

	return authMethods, nil
}

// getAgentAuth returns an ssh-agent authentication method if available
func getAgentAuth() ssh.AuthMethod {
	agentSock := os.Getenv("SSH_AUTH_SOCK")
	if agentSock == "" {
		return nil
	}

	conn, err := net.Dial("unix", agentSock)
	if err != nil {
		log.Printf("Failed to connect to ssh-agent: %v", err)
		return nil
	}

	agentClient := agent.NewClient(conn)

	// Test if the agent has any keys
	signers, err := agentClient.Signers()
	if err != nil {
		log.Printf("Failed to get signers from ssh-agent: %v", err)
		conn.Close()
		return nil
	}

	if len(signers) == 0 {
		log.Println("ssh-agent has no keys loaded")
		conn.Close()
		return nil
	}

	log.Printf("ssh-agent has %d key(s) loaded", len(signers))
	return ssh.PublicKeysCallback(agentClient.Signers)
}

// getKeyAuth creates an ssh.AuthMethod from a private key file
func getKeyAuth(keyPath string, authViaEnv bool, askForPassphrase bool) (ssh.AuthMethod, error) {
	// Expand tilde (~) to the user's home directory.
	if len(keyPath) >= 2 && keyPath[:2] == "~/" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("could not get user home directory: %w", err)
		}
		keyPath = filepath.Join(home, keyPath[2:])
	}

	key, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key from %s: %w", keyPath, err)
	}

	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		// If the key is passphrase-protected, handle based on flags
		if authViaEnv {
			return handleAuthWithEnvVar(key, keyPath)
		} else if askForPassphrase {
			return handleAuthWithCachedPassphrase(key, keyPath)
		} else {
			log.Printf("Private key %s appears to be encrypted but -ask-for-passphrase flag not set", keyPath)
			log.Println("Options:")
			log.Println("  1. Use ssh-agent: ssh-add ~/.ssh/id_rsa")
			log.Println("  2. Use environment variable: export SSH_KEY_PASSPHRASE='your_passphrase' and add -auth-via-env flag")
			log.Println("  3. Add -ask-for-passphrase flag to prompt for passphrase")
			return nil, nil // Return nil auth method instead of error
		}
	}

	return ssh.PublicKeys(signer), nil
}

// handleAuthWithEnvVar handles authentication using environment variable
func handleAuthWithEnvVar(key []byte, keyPath string) (ssh.AuthMethod, error) {
	envPassphrase := os.Getenv("SSH_KEY_PASSPHRASE")

	var passphrase []byte
	if envPassphrase != "" {
		passphrase = []byte(envPassphrase)
		log.Println("Using passphrase from SSH_KEY_PASSPHRASE environment variable")
	} else {
		log.Printf("SSH_KEY_PASSPHRASE not set for encrypted key %s", keyPath)
		log.Println("Either set the environment variable or use -ask-for-passphrase flag")
		return nil, fmt.Errorf("SSH_KEY_PASSPHRASE environment variable not set")
	}

	signer, err := ssh.ParsePrivateKeyWithPassphrase(key, passphrase)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key with passphrase: %w", err)
	}

	return ssh.PublicKeys(signer), nil
}

// handleAuthWithCachedPassphrase handles authentication with in-memory caching
// This function is only called when askForPassphrase is true
func handleAuthWithCachedPassphrase(key []byte, keyPath string) (ssh.AuthMethod, error) {
	if cachedPassphrase == nil {
		fmt.Printf("Private key appears to be encrypted. Enter passphrase for %s: ", keyPath)
		passphrase, err := term.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			return nil, fmt.Errorf("failed to read passphrase: %w", err)
		}
		fmt.Println() // Add newline after password input

		// Cache the passphrase for future use
		cachedPassphrase = make([]byte, len(passphrase))
		copy(cachedPassphrase, passphrase)

		// Clear the original passphrase from memory
		for i := range passphrase {
			passphrase[i] = 0
		}
	}

	signer, err := ssh.ParsePrivateKeyWithPassphrase(key, cachedPassphrase)
	if err != nil {
		// If cached passphrase failed, clear it and try again
		clearCachedPassphrase()
		fmt.Printf("Incorrect passphrase. Enter passphrase for %s: ", keyPath)
		passphrase, err := term.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			return nil, fmt.Errorf("failed to read passphrase: %w", err)
		}
		fmt.Println() // Add newline after password input

		// Cache the new passphrase
		cachedPassphrase = make([]byte, len(passphrase))
		copy(cachedPassphrase, passphrase)

		// Clear the original passphrase from memory
		for i := range passphrase {
			passphrase[i] = 0
		}

		signer, err = ssh.ParsePrivateKeyWithPassphrase(key, cachedPassphrase)
		if err != nil {
			clearCachedPassphrase()
			return nil, fmt.Errorf("failed to parse private key with passphrase: %w", err)
		}
	}

	return ssh.PublicKeys(signer), nil
}

// clearCachedPassphrase securely clears the cached passphrase from memory
func clearCachedPassphrase() {
	if cachedPassphrase != nil {
		for i := range cachedPassphrase {
			cachedPassphrase[i] = 0
		}
		cachedPassphrase = nil
	}
}
