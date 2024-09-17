#!/usr/bin/env python2.7
import socket, sys, threading
import paramiko

# Generate keys with 'ssh-keygen -t rsa -f server.key'
HOST_KEY = paramiko.RSAKey(filename='server.key')  # Load the SSH host key
SSH_PORT = 2222  # Port to listen for incoming SSH connections
LOGFILE = 'logins.txt'  # File to log the username:password combinations
LOGFILE_LOCK = threading.Lock()  # Lock to handle file access across threads


# Define the SSH server handler class, which handles authentication and connection details
class SSHServerHandler(paramiko.ServerInterface):
    def __init__(self):
        self.event = threading.Event()  # Event for synchronization

    # Handle password-based authentication attempts
    def check_auth_password(self, username, password):
        LOGFILE_LOCK.acquire()  # Lock the logfile to prevent race conditions
        try:
            # Log the attempted username and password to the log file
            logfile_handle = open(LOGFILE, "a")
            print("New login: " + username + ":" + password)
            logfile_handle.write(username + ":" + password + "\n")
            logfile_handle.close()
        finally:
            LOGFILE_LOCK.release()  # Release the lock after logging
        return paramiko.AUTH_FAILED  # Always fail authentication (since this is a honeypot)

    # Only allow password authentication (disable other auth methods like public key)
    def get_allowed_auths(self, username):
        return 'password'


# Function to handle an individual client connection
def handleConnection(client):
    transport = paramiko.Transport(client)  # Create an SSH transport over the client connection
    transport.add_server_key(HOST_KEY)  # Add the server's host key

    # Instantiate the SSH server handler to handle authentication requests
    server_handler = SSHServerHandler()

    # Start the SSH server with the server handler
    transport.start_server(server=server_handler)

    # Accept a new channel (e.g., shell, exec) from the client, with a timeout of 1 second
    channel = transport.accept(1)

    # If the channel is successfully created, close it (no interaction needed)
    if not channel is None:
        channel.close()


# Main function to start the server and listen for connections
def main():
    try:
        # Create a new TCP socket
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,
                                 1)  # Reuse address to avoid socket binding errors
        server_socket.bind(('', SSH_PORT))  # Bind the socket to the specified port
        server_socket.listen(100)  # Listen for up to 100 connections at once

        # Enable Paramiko logging (optional, can be useful for debugging)
        paramiko.util.log_to_file('paramiko.log')

        # Accept incoming connections in an infinite loop
        while True:
            try:
                # Accept a client connection
                client_socket, client_addr = server_socket.accept()
                # Use threading.Thread to handle the connection in a new thread
                thread = threading.Thread(target=handleConnection, args=(client_socket,))
                thread.start()
            except Exception as e:
                print("ERROR: Client handling")
                print(e)

    except Exception as e:
        print("ERROR: Failed to create socket")
        print(e)
        sys.exit(1)  # Exit if the socket couldn't be created


# Run the main function when the script is executed
if __name__ == "__main__":
    main()