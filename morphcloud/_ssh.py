import os
import sys
import tty
import fcntl
import select
import socket
import signal
import struct
import termios
import threading

import paramiko


def get_terminal_size():
    """Get the size of the terminal window."""
    try:
        # Initialize winsize structure
        size = fcntl.ioctl(sys.stdin.fileno(), termios.TIOCGWINSZ, ' ' * 8)
        rows, cols, xpix, ypix = struct.unpack('HHHH', size)
        return rows, cols
    except:
        return (24, 80)


def interactive_shell(chan):
    """Create an interactive shell session"""

    def sigwinch_handler(signum, frame):
        """Handle terminal window resize events."""
        rows, cols = get_terminal_size()
        chan.resize_pty(width=cols, height=rows)

    # Set up signal handler for window resize
    signal.signal(signal.SIGWINCH, sigwinch_handler)

    # Get the original terminal settings
    oldtty = termios.tcgetattr(sys.stdin)
    try:
        # Set the terminal to raw mode
        tty.setraw(sys.stdin.fileno())
        chan.settimeout(0.0)

        # Set initial window size
        sigwinch_handler(None, None)

        while True:
            # Wait for input from the channel or stdin
            r, w, e = select.select([chan, sys.stdin], [], [])
            if chan in r:
                try:
                    x = chan.recv(1024)
                    if len(x) == 0:
                        break
                    # Write the output to stdout
                    os.write(sys.stdout.fileno(), x)
                except Exception:
                    break
            if sys.stdin in r:
                x = os.read(sys.stdin.fileno(), 1024)
                if len(x) == 0:
                    break
                # Send the input to the channel
                chan.send(x)

    finally:
        # Restore the original terminal settings
        termios.tcsetattr(sys.stdin, termios.TCSADRAIN, oldtty)


def ssh_connect(hostname, username, password=None, key_filename=None, port=22, command=None):
    """Establish SSH connection and execute a command or start interactive session"""
    try:
        # Create a new SSH client
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        # Connect to the remote server
        connect_kwargs = {"hostname": hostname, "username": username, "port": port}

        if password:
            connect_kwargs["password"] = password
        if key_filename:
            connect_kwargs["key_filename"] = key_filename

        ssh.connect(**connect_kwargs)

        rows, cols = get_terminal_size()
        term = os.getenv('TERM', 'xterm')

        if command:
            # Open a new session
            channel = ssh.get_transport().open_session()
            # Request a pseudo-terminal
            channel.get_pty(term=term, width=cols, height=rows)
            # Execute the command
            channel.exec_command(command)
            # Use interactive_shell to handle input/output
            interactive_shell(channel)
        else:
            # Get an interactive shell with the correct terminal settings
            channel = ssh.invoke_shell(term=term, width=cols, height=rows)
            # print("Connected to", hostname)
            interactive_shell(channel)

    except Exception as e:
        print(f"Connection failed: {str(e)}")
    finally:
        if "ssh" in locals():
            ssh.close()


def forward_tunnel(local_port, remote_port, ssh_host, ssh_port=22, ssh_username=None, ssh_password=None):
    """
    Forward a local port to a remote port on the SSH server with verbose logging.
    """
    def handler(client_socket, channel):
        try:
            # print(f"New connection handler started")
            while True:
                r, w, x = select.select([client_socket, channel], [], [], 1.0)
                if client_socket in r:
                    data = client_socket.recv(4096)
                    if len(data) == 0:
                        # print("Client closed connection")
                        break
                    # print(f"Client -> Server: {len(data)} bytes")
                    channel.send(data)
                if channel in r:
                    data = channel.recv(4096)
                    if len(data) == 0:
                        # print("Server closed connection")
                        break
                    # print(f"Server -> Client: {len(data)} bytes")
                    client_socket.send(data)
        except Exception as e:
            print(f'Handler error: {str(e)}')
        finally:
            print("Cleaning up connection")
            channel.close()
            client_socket.close()

    try:
        print(f"Connecting to SSH server {ssh_host}:{ssh_port}")
        client = paramiko.SSHClient()
        client.load_system_host_keys()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        client.connect(
            ssh_host,
            ssh_port,
            username=ssh_username,
            password=ssh_password
        )
        print("SSH connection established")
        
        transport = client.get_transport()
        
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
        server.bind(('127.0.0.1', local_port))
        server.listen(5)
        
        print(f"Local server listening on localhost:{local_port}")
        print(f"Forwarding to {ssh_host}:{remote_port}")
        
        while True:
            try:
                client_socket, addr = server.accept()
                print(f"New connection from {addr}")
                # print(f"Opening channel to remote port {remote_port}")
                
                channel = transport.open_channel(
                    'direct-tcpip',
                    ('127.0.0.1', remote_port),  # Connect to localhost on remote
                    client_socket.getpeername()
                )
                
                if channel is None:
                    print("Failed to create channel")
                    client_socket.close()
                    continue
                
                # print("Channel established successfully")
                thr = threading.Thread(target=handler, args=(client_socket, channel))
                thr.daemon = True
                thr.start()
                
            except KeyboardInterrupt:
                print("\nShutting down...")
                break
            except Exception as e:
                print(f'Connection error: {str(e)}')
                
    except Exception as e:
        print(f'Forward server error: {str(e)}')
    finally:
        try:
            server.close()
            client.close()
            print("Cleanup complete")
        except:
            pass


def main():
    # Example: Forward local port 8080 to port 80 on the SSH server
    forward_tunnel(
        local_port=8080,
        remote_port=80,
        ssh_host='remote.server.com',
        ssh_username='username',
        ssh_password='password'
    )

if __name__ == '__main__':
    main()

if __name__ == "__main__":
    MORPH_API_KEY = os.getenv("MORPH_API_KEY", "")

    if not MORPH_API_KEY:
        print("MORPH_API_KEY environment variable not set")
        sys.exit(1)

    if len(sys.argv) < 2:
        print("Usage: python ssh.py <instance_id> [command]")
        sys.exit(1)

    instance_id = sys.argv[1]
    command = ' '.join(sys.argv[2:]) if len(sys.argv) > 2 else None

    hostname = "localhost"
    port = 2222

    username = instance_id + ":" + MORPH_API_KEY

    ssh_connect(hostname, username, port=port, command=command)
