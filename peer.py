from socket import *
import threading
import random
import json
import sys
import time
from database import P2PChatDB
from colorama import init, Fore, Style
from pyfiglet import Figlet
import logging
import hashlib
from bson import ObjectId

# Initialize colorama
init()

# Initialize Figlet with a chosen font
fig = Figlet(font='slant')

chatrooms = []
activeChatroom = None
# Client setup
SERVER_HOST = 'localhost'
SERVER_TCP = 5000
SERVER_UDP = 5001  # Use the same port for UDP communication as specified in the server

NOT_OK_MESSAGE = "not ok"

# UDP socket setup
udp_socket = socket(AF_INET, SOCK_DGRAM)
addresses = {}

client = None  # Initialize the client socket

# Variable to track login status
is_logged_in = False

# Variable to control the hello thread
send_hello = True


# Function to create and connect the client socket
def create_and_connect_client(max_attempts=5, retry_interval=3, final_retry_interval=60):
    global client

    for attempt in range(1, max_attempts + 1):
        try:
            client = socket(AF_INET, SOCK_STREAM)
            client.connect((SERVER_HOST, SERVER_TCP))
            print_colored("Connection successful.", Fore.GREEN)
            return  # If successful, exit the function
        except ConnectionRefusedError:
            print_colored(
                f"Unable to connect to the server. Retrying in {retry_interval} seconds... (Attempt {attempt}/{max_attempts})",
                Fore.RED)
            time.sleep(retry_interval)

    # If still not connected after max_attempts, wait for a longer interval
    print_colored(
        f"Failed to connect after {max_attempts} attempts. Waiting for {final_retry_interval} seconds before exiting.",
        Fore.BLUE)
    time.sleep(final_retry_interval)

    # Attempt one more time after the longer interval
    try:
        client = socket(AF_INET, SOCK_STREAM)
        client.connect((SERVER_HOST, SERVER_TCP))
        print_colored("Connection successful.", Fore.GREEN)
    except ConnectionRefusedError:
        print_colored(
            "Final attempt failed. Exiting the program. Please try again later. Our server might be down momentarily.",
            Fore.RED)
        sys.exit()


# Function to handle disconnection or errors
def handle_disconnection():
    global client, is_logged_in
    print_colored("Disconnected from the server. Reconnecting...", Fore.RED)
    is_logged_in = False  # Reset login status
    if client:
        client.close()  # Close the existing client socket
    create_and_connect_client()  # Attempt to create and connect a new client socket


# Function to send a single "HELLO" message over UDP
def send_hello_message_udp():
    hello_message = {
        "type": "hello",
        # "username": username
    }
    udp_socket.sendto(json.dumps(hello_message).encode('utf-8'), ('localhost', SERVER_UDP))


# Modify the start_hello_thread function to use UDP
def start_hello_thread():
    hello_thread = threading.Thread(target=send_continuous_hello_udp)
    hello_thread.daemon = True
    hello_thread.start()


# Function to send a logout request to the server
def send_continuous_hello_udp():
    global send_hello
    while send_hello:
        if is_logged_in:
            send_hello_message_udp()
        time.sleep(1)  # Send 'HELLO' every second


# Handle server responses
def handle_server_response(message_data):
    global is_logged_in
    if message_data.get('type') == 'get_online_users_response':
        online_users = message_data.get('users')
        if online_users is not None:
            print("Online users: " + ', '.join(online_users))
        else:
            print("No online users.")
            print_colored("Disconnected from the server. Reconnecting...", Fore.LIGHTMAGENTA_EX)
    elif message_data.get('type') == 'login_response':
        if message_data.get('status') == 'ok':
            print("Login successful.")
            is_logged_in = True
    elif message_data.get('type') == 'logout_response':
        if message_data.get('status') == 'ok':
            print("Logout successful.")
            is_logged_in = False
    elif message_data.get('type') == 'create_account_response':
        if message_data.get('status') == 'ok':
            print("Account creation successful.")

    elif message_data.get('type') == 'chatroom':
        if message_data.get('method') == 'get all':
            return message_data.get('chatrooms')

    elif message_data.get('type') == 'welcome':
        print(f"Server: {message_data.get('msg')}")
    else:
        print(f"Ignored unexpected response: {message_data}")


def send_exit():
    # Construct the exit message
    message_data = {
        "type": "exit"
    }
    # Send the exit request to the server
    client.send(json.dumps(message_data).encode('utf-8'))
    print_colored("Exiting the chat...", Fore.LIGHTYELLOW_EX)

    try:
        # Wait for the exit response from the server
        response = wait_for_response('exit_response')

        if response:
            if response.get('status') == 'ok':
                print_colored("Exit successful.", Fore.GREEN)
                if client:
                    client.close()
                return True  # Indicate successful exit
            else:
                print_colored(f"Exit failed. Received response: {response}", Fore.RED)
                return False  # Indicate a failed exit
        else:
            print_colored("Did not receive a valid response from the server.", Fore.RED)
            return False  # Indicate a failed exit

    except Exception as e:
        print_colored(f"Error waiting for exit response: {e}", Fore.RED)
        return False  # Indicate a failed exit


# Global variable to track received messages
received_messages = []

# Handle receiving messages from the server
# Initialize the logging module
logging.basicConfig(level=logging.DEBUG)


# Handle receiving messages from the server
# Modify the receive function to return the received message
def receive():
    try:
        message = client.recv(1024).decode('utf-8')
        if message:
            message_data = json.loads(message)
            handle_server_response(message_data)  # Process server responses
            return message_data
    except socket.error as se:
        # Handle network-related errors (e.g., connection reset, timeout)
        logging.error(f"Network error occurred: {se}")
        # Optionally, you can decide whether to attempt reconnection here
        handle_disconnection()
    except Exception as e:
        # Handle other types of errors
        logging.error(f"An error occurred while receiving: {e}")
    return None


# Modify the send_login function to check the received message
def send_login(username, password):
    # Construct the login message
    password = hashlib.sha256(password.encode('utf-8')).hexdigest()

    receivingSocket = socket(AF_INET, SOCK_STREAM)
    while True:  # loop to generate random port and bind it to the socket
        try:
            port = random.randint(1000, 5000)  # code to generate random port
            receivingSocket.bind((gethostname(), port))
            break
        except socket.error as e:
            pass

    message_data = {
        "type": "login",
        "username": username,
        "password": password,
        "port": port,  # port to be sent to the server
    }

    try:
        # Send the login request to the server
        client.send(json.dumps(message_data).encode('utf-8'))

        # Wait for the login response from the server
        response = wait_for_response('login_response')

        if response:
            if response.get('status') == 'ok':
                print_colored("Login successful.", Fore.LIGHTCYAN_EX)
                receivingSocket.listen(10)
                server = PeerServer(receivingSocket)
                server.start()
                return True  # Indicate successful login attempt
            else:
                print_colored(f"Login failed. Received response: {response}", Fore.RED)
                return False  # Indicate a failed login attempt
        else:
            print_colored("Did not receive a valid response from the server.", Fore.RED)
            return False  # Indicate a failed login attempt

    except Exception as e:
        print_colored(f"Error sending login request: {e}", Fore.RED)
        return False  # Indicate a failed login attempt


# Add a function to wait for a specific response type
def wait_for_response(expected_type):
    try:
        while True:
            message = client.recv(1024).decode('utf-8')
            if message:
                message_data = json.loads(message)
                if message_data.get('type') == expected_type:
                    return message_data
    except Exception as e:
        print_colored(f"An error occurred while waiting for response: {e}", Fore.RED)
    return None


# Start the receiving thread
def start_receiving_thread():
    receive_thread = threading.Thread(target=receive)
    receive_thread.daemon = True  # This ensures the thread will close when the main program exits
    receive_thread.start()


# Function to send a logout request to the server
def send_logout():
    global is_logged_in, send_hello
    # Construct the logout message
    message_data = {
        "type": "logout"
    }
    # Send the logout request to the server
    client.send(json.dumps(message_data).encode('utf-8'))

    # Wait for the login response from the server
    response = wait_for_response('logout_response')

    if response:
        if response.get('status') == 'ok':
            is_logged_in = False
            print_colored("Logout successful.", Fore.LIGHTGREEN_EX)
            send_hello = False  # Set send_hello to False after successful logout
            return True  # Indicate successful logout attempt
        else:
            print_colored(f"Logout failed. Received response: {response}", Fore.RED)
            return False  # Indicate a failed logout attempt
    else:
        print_colored("Did not receive a valid response from the server.", Fore.RED)
        return False  # Indicate a failed logout attempt


# Function to get online users from the server
def send_get_online_users():
    message_data = {
        "type": "get_online_users"
    }
    try:
        # Send the message to the server
        client.send(json.dumps(message_data).encode('utf-8'))

        # Wait for the response from the server
        response = wait_for_response('get_online_users_response')

        if response:
            online_users = response.get('users')
            if online_users is not None:

                return online_users

            else:
                print_colored("No online users.", Fore.MAGENTA)
        else:
            print_colored("Did not receive a valid response from the server.", Fore.RED)

    except Exception as e:
        print_colored(f"Error sending 'Get Online Users' request: {e}", Fore.RED)


def get_chatrooms() -> list | None:
    req = {
        "type": "chatroom",
        "method": "get all",
    }
    client.send(json.dumps(req).encode('utf-8'))
    message = client.recv(1024).decode('utf-8')
    if message:
        message_data = json.loads(message)
        res = handle_server_response(message_data)  # Process server responses
        return res


def send_create_account(username, password):
    global is_logged_in

    passwordHashed = hashlib.sha256(password.encode('utf-8')).hexdigest()

    # Construct the create account message
    message_data = {
        "type": "create_account",
        "username": username,
        "password": passwordHashed  # hash password then send it to server
    }

    try:
        # Send the create account request to the server
        client.send(json.dumps(message_data).encode('utf-8'))

        # Wait for the create account response from the server
        response = wait_for_response('create_account_response')

        if response:
            if response.get('status') == 'ok':
                print_colored("Account creation successful.", Fore.LIGHTGREEN_EX)
                is_logged_in = send_login(username, password)
                return True  # Indicate successful account creation
            else:
                print_colored(f"Account creation failed. Received response: {response}", Fore.RED)
                return False  # Indicate a failed account creation
        else:
            print_colored("Did not receive a valid response from the server.", Fore.RED)
            return False  # Indicate a failed account creation

    except Exception as e:
        print_colored(f"Error sending create account request: {e}", Fore.RED)
        return False  # Indicate a failed account creation


# Modify print_colored function to include more styling options
def print_colored(message, color=Fore.WHITE, style=Style.NORMAL):
    print(f"{style}{color}{message}{Style.RESET_ALL}")


# Function to print colored ASCII art
def print_ascii_art(message, font='slant', color=Fore.CYAN):
    fig = Figlet(font=font)
    ascii_art = fig.renderText(message)
    print_colored(ascii_art, color=color)


import re


def is_strong_password(password):
    # Define criteria for a strong password
    # At least 8 characters
    # At least one uppercase letter
    # At least one lowercase letter
    # At least one digit
    # At least one special character (e.g., !@#$%^&*)
    # pattern = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$')

    # Check if the password matches the defined pattern
    # return bool(re.match(pattern, password))
    return True


def get_password_from_user():
    while True:
        password = input("Enter your password: ")
        if is_strong_password(password):
            return password
        else:
            print_colored("Password does not meet the criteria for strength. Please try again.", Fore.LIGHTRED_EX)


def chatroom_to_server(method: str, username: str, chatroom_id: ObjectId, message: str = None) -> dict | None:
    """
    method:  "join" | "leave" | "close"  | "open"
    username: str
    chatroom_id: ObjectId
    message: str
    open: reenter a chatroom
    join: join a chatroom
    leave: leave a chatroom permanently
    close: close a chatroom
    response: chatrooms[] array of users
    """
    global isChatting
    global activeChatroom
    global chatrooms
    chatroom_id=chatroom_id['$oid']
    message_data = {
        "type": "chatroom",
        "method": method,
        "chatroom_id": chatroom_id,
        "username": username,
        "message": message
    }
    client.send(json.dumps(message_data).encode('utf-8'))
    response = wait_for_response('chatroom')
    if response.get('status') == NOT_OK_MESSAGE:
        print_colored("Did not receive a valid response from the server.", Fore.RED)

    elif method == "join":
        print_colored(f"joined chatroom {chatroom_id} successfully", Fore.LIGHTCYAN_EX)
        isChatting = True
        activeChatroom = response.get('chatroom')

    elif method == "open":
        print_colored(f"opened chatroom {chatroom_id} successfully", Fore.LIGHTCYAN_EX)
        isChatting = True
        activeChatroom = response.get('chatroom')

    elif method == "leave":
        print_colored(f"left chatroom {chatroom_id} successfully", Fore.LIGHTCYAN_EX)
        isChatting = False
        activeChatroom = None
        chatrooms = get_chatrooms()

    elif method == "close":
        print_colored(f"closed chatroom {chatroom_id} successfully", Fore.LIGHTCYAN_EX)
        isChatting = False
        activeChatroom = None


def send_message(chatroom: dict, username: str, userReciever: dict, message: str):
    if isinstance(userReciever, str):
        userReciever = getUserByUsername(userReciever)
    message_data = {
        "type": "message",
        "method": "chat",
        "chatroom_id": ""if chatroom is None else chatroom['_id'],
        "username": username,
        "message": message,
    }
    user = socket(AF_INET, SOCK_STREAM)
    user.connect((gethostname(), userReciever['address']['portRecv']))
    user.send(json.dumps(message_data).encode('utf-8'))
    user.close()


def join_chatroom(chatroom:dict, username:str):
    global isChatting
    global chatPeer
    global username_
    global activeChatroom
    global chatrooms
    print_colored(f"joining chatroom\nto leave the chatroom permentally :q,to close the chatroom :c, ",Fore.LIGHTCYAN_EX)
    while isChatting:
        message = input(f"{username_}: ").strip()
        if message == ":q":  # quit chatroom
            chatroom_to_server("leave", username_, activeChatroom['_id'])
            isChatting = False
            chatrooms = get_chatrooms()
            activeChatroom = None
        elif message == ":c":  # close chatroom
            chatroom_to_server("close", username_, activeChatroom['_id'])
            isChatting = False
            chatrooms = get_chatrooms()
            activeChatroom = None
        else:
            for user in activeChatroom["activeUsers"]:
                if user != username_:
                    send_message(activeChatroom, username_, user, message)


def join_one2one(user:dict, username:str):
    print_colored(f"chatting started\nto leave the chat :q", Fore.LIGHTCYAN_EX)
    global isChatting
    global chatPeer
    global username_
    while isChatting:
        message = input(f"{username}: ").strip()
        if message == ":q":  # quit chatroom
            send_message(None, username=username_, userReciever=user, message=message)
            isChatting = False
            chatPeer = None
        else:
            send_message(None, username=username_, userReciever=user, message=message)


class PeerServer(threading.Thread):
    # Peer server initialization
    def __init__(self, socket_):
        global isChatting
        threading.Thread.__init__(self)
        self.receivingSocket = socket_


    def run(self):
        global activeChatroom
        global username_
        global chatPeer
        global isChatting
        global chatrooms
        global busywait

        while True:
            # Wait for a connection
            connectionSocket, addr = self.receivingSocket.accept()
            message = connectionSocket.recv(1024).decode('utf-8')
            if message:
                message_data = json.loads(message)

                if message_data.get('type') == "chatroom" :
                    if message_data.get('method') == "join":        # user joined chat
                        activeChatroom = message_data.get('chatroom')
                        print_colored(f"user {message_data.get('username')} joined chatroom successfully", Fore.LIGHTCYAN_EX)
                        
                    elif message_data.get('method') == "open":        # user joined chat
                        activeChatroom = message_data.get('chatroom')
                        print_colored(f"user {message_data.get('username')} joined chatroom successfully", Fore.LIGHTCYAN_EX)
                        
                    elif message_data.get('method') == "leave":        # user joined chat
                        activeChatroom = message_data.get('chatroom')
                        print_colored(f"user {message_data.get('username')} left chatroom", Fore.LIGHTCYAN_EX)
                        
                    elif message_data.get('method') == "close":        # user joined chat
                        activeChatroom = message_data.get('chatroom')
                        print_colored(f"user {message_data.get('username')} closed chatroom", Fore.LIGHTCYAN_EX)
                        
                    elif message_data.get('method') == "invitation":        # user joined chat
                        activeChatroom = message_data.get('chatroom')
                        print_colored(f"you were added to a chatroom {activeChatroom['usernames']}", Fore.LIGHTCYAN_EX)
                        

                elif message_data.get('type') == "chat_request":  # chat request
                    if message_data.get('method') == "invite":  # chat request
                        if  isChatting is False:
                            print(f"chat request from {message_data.get('username')} enter ok to accept, reject to reject")
                            chatPeer = getUserByUsername(message_data.get('username'))
                            isChatting = True
                            busywait=True
                            while busywait:
                                pass
                            if chatPeer:  # didnt reject
                                res={"type": "chat_request","answer": "accept","username": username_}
                                connectionSocket.send(json.dumps(res).encode('utf-8'))
                            elif chatPeer is None:
                                res={"type": "chat_request","answer": "reject","username": username_}
                                connectionSocket.send(json.dumps(res).encode('utf-8'))
                            # block main and take input from user to accept or reject the chat request then send the response to the server
                            # res={"type": "chat_request","answer": "busy","username": username_}
                            # connectionSocket.send(json.dumps(res).encode('utf-8'))
                            # isChatting = True
                            # chatPeer = getUserByUsername(message_data.get('username'))
                        else: # busy
                            res={"type": "chat_request","answer": "busy","username": username_}
                            connectionSocket.send(json.dumps(res).encode('utf-8'))
                    
                if message_data.get('type') == "message" and isChatting == True and chatPeer:
                    if message_data.get('message') == ":q":  # quit chatroom
                        isChatting = False
                        chatPeer = None
                        print(f"user chat ended")
                    else:
                        print(f"{chatPeer['username']}: {message_data.get('message')}")
                    
                if message_data.get('type') == "message" and isChatting == True and activeChatroom:
                        print(f"{message_data.get('username')}: {message_data.get('message')}")

                # if message_data.get('type') == "chatroom" and isChatting == True and chatPeer:
                    # print(f"{chatPeer['username']}: {message_data.get('message')}")

                # if message_data.get('type') == "message" and isChatting == True:
                    # print(f"{message_data.get('username')}: {message_data.get('message')}")
                    
            connectionSocket.close()


isChatting = False
chatPeer = None
username_ = None
busywait=False

def getUserByUsername(username: str):
    req = {
        "type": "user",
        "method": "get",
        "username": username,
    }
    client.send(json.dumps(req).encode('utf-8'))
    message = client.recv(1024).decode('utf-8')
    if message:
        message_data = json.loads(message)
        return message_data['user']


# Modify main function to start the threads
def main():
    global is_logged_in, send_hello
    global chatPeer
    global isChatting
    global username_
    global chatrooms
    global busywait

    print_ascii_art("P2P Chat Client", font='slant', color=Fore.LIGHTYELLOW_EX)

    # Create and connect the client socket
    create_and_connect_client()

    start_receiving_thread()
    start_hello_thread()

    try:
        while True:
            print_colored("Enter the number of the command:", Fore.CYAN)

            if not is_logged_in:
                print_colored("1. Login\n2. Create Account\n3. Exit", Fore.YELLOW)
            else:
                print_colored(
                    "1. Logout\n2. Get Online Users\n3. create chat room\n4. join created chat rooms\n5. Chat with someone\n6. Exit",
                    Fore.YELLOW)

            command = input("Command: ")

            valid_command = False

            if not is_logged_in:
                if command == "1":  # Login
                    isChatting=True
                    username = input("Username: ")
                    password = input("Password: ")
                    isChatting=False
                    is_logged_in = send_login(username, password)
                    if is_logged_in:
                        print_colored(f"Welcome back, {username}!", Fore.GREEN)
                        chatrooms = get_chatrooms()
                        send_hello_message_udp()
                        username_ = username
                    valid_command = True
                elif command == "2":
                    isChatting=True
                    username = input("Choose a username: ")
                    isChatting=False
                    password = get_password_from_user()
                    # Send create account request
                    create_account_success = send_create_account(username, password)

                    if create_account_success:
                        username_ = username
                        print_colored(f"Welcome, {username}! You are now logged in.", Fore.GREEN)
                    else:
                        print_colored("Account creation failed. Please try again.", Fore.RED)
                    valid_command = True
                elif command == "3":
                    send_hello = False
                    send_exit()
                    if client:
                        client.close()
                    time.sleep(1)
                    break

            else:
                # if isChatting is False and chatPeer:  # if a one-to-one chat request accepted
                    # valid_command = True
                    # join_one2one(chatPeer, username)
                    # continue

                if command == "1":
                    print_colored("Logging out...", Fore.LIGHTYELLOW_EX)
                    send_logout()
                    valid_command = True
                elif command == "2":
                    print_colored("Online users: " + ', '.join(send_get_online_users()), Fore.LIGHTMAGENTA_EX)
                    valid_command = True

                elif command == "3":  # 3. create chat room - 4. join created chat rooms
                    valid_command = True
                    isChatting=True
                    arguments = [username, *input("insert usernames to invite to the channel: ").split()]
                    isChatting=False
                    if isChatting == True:
                        continue
                    onlineUsers = send_get_online_users()
                    for user in arguments:
                        if user not in onlineUsers:
                            arguments.remove(user)
                    if len(arguments) == 1:
                        print(f"no online users to create a chat with")
                        continue
                    print(f"creating a chatroom containing the following users {arguments}")
                    req = {
                        "type": "chatroom",
                        "method": "create",
                        "users": arguments,  # usernames to be sent to the server
                    }
                    client.send(json.dumps(req).encode('utf-8'))

                    # just create a channel



                elif command == "4":  # 4. join created chat rooms
                    print(f"chatrooms: {None if (chatrooms := get_chatrooms()) else chatrooms}")
                    for index, chatroom in enumerate(get_chatrooms()):
                        print(f"{index} - users: {chatroom['usernames']}")
                    if len(chatrooms) == 0:
                        print(f"no chatrooms to join")
                        continue
                    isChatting=True
                    choice = int(input("command:"))
                    isChatting=False
                    if isChatting == True:
                        continue

                    if choice >= len(chatrooms):
                        print(f"invalid choice")
                        continue

                    chatroom_to_server("open", username, chatrooms[choice]['_id'], None)
                    isChatting = True
                    join_chatroom(activeChatroom, username)
                    valid_command = True


                elif command == "5":  # 5. Chat with someone
                    valid_command = True
                    isChatting=True
                    argument = input("insert usernames to invite to the channel: ")
                    isChatting=False
                    if isChatting == True:
                        continue
                    if argument == username_:
                        print(f"cant chat with yourself")
                        continue
                    chatPeer = getUserByUsername(argument)
                    if chatPeer['online'] == False:
                        print(f"cant chat with offline user")
                        chatPeer = None
                        continue
                    print(f"sent a chat request with user {argument}")
                    req = { # chat request
                        "type": "chat_request",
                        "method": "invite",
                        "username": username,
                    }
                    chatPeerSocket = socket(AF_INET, SOCK_STREAM)
                    chatPeerSocket.connect((gethostname(), chatPeer['address']['portRecv']))
                    chatPeerSocket.send(json.dumps(req).encode('utf-8'))
                    res = json.loads(chatPeerSocket.recv(1024).decode('utf-8'))
                    if res.get('answer') == "busy":
                        print(f"user is busy")
                    elif res.get('answer') == "accept":
                        chatPeer = getUserByUsername(argument)
                        isChatting = True
                        join_one2one(chatPeer, username_)
                    elif res.get('answer') == "reject":
                        print(f"chat request rejected")
                        chatPeer = None
                    
                elif command =="ok":
                    valid_command = True
                    busywait=False
                    join_one2one(chatPeer, username_)
                    
                elif command =="reject":
                    valid_command = True
                    isChatting=False
                    chatPeer=None
                    busywait=False
                    print(f"chat request rejected")
                    

                elif command == "6":
                    send_hello = False
                    send_exit()
                    if client:
                        client.close()
                    time.sleep(1)
                    break

            if not valid_command:
                # Print error messages in red
                print_colored("Please choose a correct command.", Fore.RED)

    except Exception as main_exception:
        # Print exception messages in red
        print_colored(f"An error occurred: {main_exception}", Fore.RED)

    finally:
        # Clean up the UDP socket
        udp_socket.close()


# Start the client
if __name__ == "__main__":
    main()
