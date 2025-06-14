package session

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

// StartInteractiveShell opens a fully interactive PTY shell on the remote server.
func StartInteractiveShell(client *ssh.Client) {
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
