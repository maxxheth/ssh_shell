# Project ssh_shell

This is a basic SSH shell application written in Go. It allows users to connect to a remote server via SSH and execute commands interactively.
## Table of Contents
- [Project ssh\_shell](#project-ssh_shell)
	- [Table of Contents](#table-of-contents)
	- [Usage](#usage)
	- [Contributing](#contributing)
	- [License](#license)
	- [Authors](#authors)
	- [Getting Started](#getting-started)
	- [MakeFile](#makefile)
## Usage
To use the SSH shell application, follow these steps:
1. Ensure you have Go installed on your machine.
2. Clone the repository:
   ```bash
   git clone https://github.com/maxxheth/ssh_shell.git
   ```
3. Navigate to the project directory:
   ```bash
   cd ssh_shell
   ```
4. Build the application:
   ```bash
   make build
   ```
5. Run the application:
   ```bash
   make run
   ```
6. Connect to a remote server by providing the SSH credentials:
   ```bash
   ./ssh_shell -host <remote_host> -port <remote_port> -user <username>
   ```
   For help with command-line options, you can run:
   ```bash
   ./ssh_shell -help
   ```
   This will display the available options and their descriptions.

7. Once connected, you can execute commands interactively in the remote shell.
## Contributing
Contributions are welcome! If you have suggestions for improvements or new features, please open an issue or submit a pull request. Please ensure that your code adheres to the project's coding standards and includes appropriate tests.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
## Authors
- Maximillian Heth - [maxxheth](https://github.com/maxxheth)

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes. See deployment for notes on how to deploy the project on a live system.

## MakeFile

Run build make command with tests
```bash
make all
```

Build the application
```bash
make build
```

Run the application
```bash
make run
```

Live reload the application:
```bash
make watch
```

Run the test suite:
```bash
make test
```

Clean up binary from the last build:
```bash
make clean
```
