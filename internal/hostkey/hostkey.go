package hostkey

import (
	"bufio"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
)

// VerifyHostKey returns a HostKeyCallback that verifies the remote host's key
// against the known_hosts file, with fallback to user confirmation for unknown hosts
func VerifyHostKey(knownHostsPath string) ssh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		// If no known_hosts path provided, use default
		if knownHostsPath == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				return fmt.Errorf("could not get user home directory: %w", err)
			}
			knownHostsPath = filepath.Join(home, ".ssh", "known_hosts")
		}

		// Check if the host key is already known
		if err := checkKnownHosts(knownHostsPath, hostname, key); err == nil {
			return nil // Host key is valid
		}

		// Host key not found or invalid, prompt user
		return promptUserForHostKey(knownHostsPath, hostname, remote, key)
	}
}

// checkKnownHosts verifies if the host key exists in the known_hosts file
func checkKnownHosts(knownHostsPath, hostname string, key ssh.PublicKey) error {
	file, err := os.Open(knownHostsPath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("known_hosts file not found")
		}
		return fmt.Errorf("failed to open known_hosts file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse the known_hosts line
		if err := parseKnownHostsLine(line, hostname, key); err == nil {
			return nil // Match found
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading known_hosts file: %w", err)
	}

	return fmt.Errorf("host key not found in known_hosts")
}

// parseKnownHostsLine parses a single line from known_hosts and checks for a match
func parseKnownHostsLine(line, hostname string, key ssh.PublicKey) error {
	parts := strings.Fields(line)
	if len(parts) < 3 {
		return fmt.Errorf("invalid known_hosts line format")
	}

	hosts := parts[0]
	keyType := parts[1]
	keyData := parts[2]

	// Check if hostname matches
	hostMatches := false
	for _, host := range strings.Split(hosts, ",") {
		if host == hostname {
			hostMatches = true
			break
		}
	}

	if !hostMatches {
		return fmt.Errorf("hostname does not match")
	}

	// Check if key type matches
	if keyType != key.Type() {
		return fmt.Errorf("key type does not match")
	}

	// Decode and compare the key
	knownKeyBytes, err := base64.StdEncoding.DecodeString(keyData)
	if err != nil {
		return fmt.Errorf("failed to decode known key: %w", err)
	}

	currentKeyBytes := key.Marshal()
	if !equalBytes(knownKeyBytes, currentKeyBytes) {
		return fmt.Errorf("host key has changed - possible man-in-the-middle attack")
	}

	return nil
}

// promptUserForHostKey prompts the user to verify an unknown host key
func promptUserForHostKey(knownHostsPath, hostname string, remote net.Addr, key ssh.PublicKey) error {
	fmt.Printf("\nThe authenticity of host '%s (%s)' can't be established.\n", hostname, remote.String())
	fmt.Printf("%s key fingerprint is:\n", key.Type())
	fmt.Printf("SHA256:%s\n", getFingerprint(key, "SHA256"))
	fmt.Printf("MD5:%s\n", getFingerprint(key, "MD5"))
	fmt.Print("Are you sure you want to continue connecting (yes/no)? ")

	var response string
	fmt.Scanln(&response)

	response = strings.ToLower(strings.TrimSpace(response))
	if response != "yes" && response != "y" {
		return fmt.Errorf("host key verification failed - connection aborted by user")
	}

	// Add the key to known_hosts
	if err := addToKnownHosts(knownHostsPath, hostname, key); err != nil {
		fmt.Printf("Warning: Failed to add host key to known_hosts: %v\n", err)
		// Continue anyway since user approved
	} else {
		fmt.Printf("Warning: Permanently added '%s' to the list of known hosts.\n", hostname)
	}

	return nil
}

// addToKnownHosts adds a host key to the known_hosts file
func addToKnownHosts(knownHostsPath, hostname string, key ssh.PublicKey) error {
	// Ensure the .ssh directory exists
	sshDir := filepath.Dir(knownHostsPath)
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		return fmt.Errorf("failed to create SSH directory: %w", err)
	}

	// Open file for appending
	file, err := os.OpenFile(knownHostsPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("failed to open known_hosts file for writing: %w", err)
	}
	defer file.Close()

	// Format the host key entry
	keyData := base64.StdEncoding.EncodeToString(key.Marshal())
	line := fmt.Sprintf("%s %s %s\n", hostname, key.Type(), keyData)

	if _, err := file.WriteString(line); err != nil {
		return fmt.Errorf("failed to write to known_hosts file: %w", err)
	}

	return nil
}

// getFingerprint generates a fingerprint for the given key
func getFingerprint(key ssh.PublicKey, algorithm string) string {
	keyBytes := key.Marshal()

	switch algorithm {
	case "SHA256":
		hash := sha256.Sum256(keyBytes)
		return base64.RawStdEncoding.EncodeToString(hash[:])
	case "MD5":
		hash := md5.Sum(keyBytes)
		parts := make([]string, len(hash))
		for i, b := range hash {
			parts[i] = fmt.Sprintf("%02x", b)
		}
		return strings.Join(parts, ":")
	default:
		return ""
	}
}

// equalBytes compares two byte slices
func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// InsecureIgnoreHostKey returns a HostKeyCallback that accepts any host key
// This should only be used for development/testing
func InsecureIgnoreHostKey() ssh.HostKeyCallback {
	return ssh.InsecureIgnoreHostKey()
}
