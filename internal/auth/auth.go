package auth

import (
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/term"
)

// Global variable to cache the passphrase
var cachedPassphrase []byte

// GetAuthMethods returns a slice of authentication methods, prioritizing ssh-agent if available
func GetAuthMethods(keyPath string, authViaEnv bool, useAgent bool, askForPassphrase bool) ([]ssh.AuthMethod, error) {
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
		ClearCachedPassphrase()
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
			ClearCachedPassphrase()
			return nil, fmt.Errorf("failed to parse private key with passphrase: %w", err)
		}
	}

	return ssh.PublicKeys(signer), nil
}

// ClearCachedPassphrase securely clears the cached passphrase from memory
func ClearCachedPassphrase() {
	if cachedPassphrase != nil {
		for i := range cachedPassphrase {
			cachedPassphrase[i] = 0
		}
		cachedPassphrase = nil
	}
}
