import json
import socket
import threading
import time
from database import P2PChatDB
from bson import ObjectId

from bson import json_util


def parse_json(data):  # convert bson to json
    return json.loads(json_util.dumps(data))


# Server setup
HOST = 'localhost'
PORT_TCP = 5000
PORT_UDP = 5001  # Choose a different port for UDP communication
# UDP socket setup
udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp_socket.bind(('localhost', PORT_UDP))

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT_TCP))
server.listen()

# Modify the accept_connections function to start the UDP thread
clients = {}
active_connections = {}  # {'connectionSocket':address}

# Initialize the database
db = P2PChatDB()

last_hello_time = {}  # {'username':lastTimeSaidHello}


# Function to handle 'HELLO' messages over UDP
def handle_hello_udp():
    while True:
        try:
            message, client_address = udp_socket.recvfrom(1024)
            if message:
                message_data = json.loads(message.decode('utf-8'))
                # Print the received "HELLO" message
                print(f"Received HELLO from {client_address}: {message_data}")
                handle_hello(None, client_address)  # Reuse the handle_hello function
        except Exception as e:
            print(f"Error in handle_hello_udp: {e}")


# Now, define the get_connection_by_address function
def get_connection_by_address(address):
    for conn, addr in active_connections.items():
        if addr == (address['ip'], address['port']):
            return conn
    return None


def send_user_chatroom(message: str):
    if message == "invite":
        pass
        # send users invitation
    elif message == "notify user accepted or rejected":
        pass
    elif message == "notify user accepted or rejected":
        pass


def broadcast_to_usernames(users: list[str], message: str):
    """
    send a message to all users using their username
    """
    for user in users:
        address = db.get_address_by_username(user)
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn.connect((socket.gethostname(), address['portRecv']))
        send_to_client(conn, message)
        conn.close()


def handle_chatroom(conn: socket, addr, message_data):
    # if message_data['usernames'] not in db.users.find({'online': True},{'username':1}):   # check if user is online
    #     response={"type":"chatroom","status":"forbidden",}
    #     send_to_client(conn,response)
    #     return False
    if message_data.get("chatroom_id"):
        chatroom_id = message_data.get("chatroom_id")
        chatroom = db.get_chatroom_by_id(chatroom_id)
        parse_json(chatroom)
    if message_data.get("username"):
        user = db.users.find_one({"username": message_data.get("username")})
        parse_json(user)

    if message_data.get("method") == "create":
        users = message_data.get("users")
        if (chatroom:=db.create_chatroom(users)):  # create a chatroom containing the person who created it
            print(f"chat room created successfully with users {users}\n")
            response = {  # message to notify users that they are invited to a chatroom
                "type": "chatroom",
                "method": "invitation",
                "users": users,
                "chatroom": parse_json(chatroom),
            }
            broadcast_to_usernames(users[1:], response)

    if message_data.get("method") == "open":
        db.user_open_chatroom(chatroom_id, user['username'])
        chatroom=db.get_chatroom_by_id(chatroom_id)
        response = {"type": "chatroom", "method": "open", "username": message_data.get("username"),"chatroom": parse_json(chatroom)}
        conn.send(json.dumps(response).encode('utf-8'))
        broadcast_to_usernames(chatroom.get('activeUsers'), response)

    elif message_data.get("method") == "join":  # message from a user to server to indicate that he processed the invitation to the chatroom
        if message_data.get("value") is False :
            return
        db.update_chatroom(chatroom_id, message_data.get("user"), True)
        chatroom=db.get_chatroom_by_id(chatroom_id)
        response = {  # message to notify users that they are invited to a chatroom
            "type": "chatroom",
            "method": "join",
            "username": message_data.get("username"),
            "chatroom": parse_json(chatroom),
        }
        broadcast_to_usernames(db.get_chatroom_by_id(chatroom_id)['activeUsers'], response)

    elif message_data.get("method") == "leave":  # message from a user to server to indicate that he processed the invitation to the chatroom
        db.update_chatroom(chatroom_id, user, False)
        chatroom=db.get_chatroom_by_id(chatroom_id)
        response = {  # message to notify users that they are invited to a chatroom
            "type": "chatroom",
            "method": "leave",
            "username": message_data.get("username"),
            "chatroom": parse_json(chatroom),
        }
        conn.send(json.dumps(response).encode('utf-8'))
        broadcast_to_usernames(chatroom.get('activeUsers'), response)

    elif message_data.get("method") == "close":
        db.user_offline_chatroom(chatroom_id, message_data.get("username"))
        chatroom=db.get_chatroom_by_id(chatroom_id)
        response = {  # message to notify users that they are invited to a chatroom
            "type": "chatroom",
            "method": "close",
            "username": message_data.get("username"),
            "chatroom": parse_json(chatroom),
        }
        conn.send(json.dumps(response).encode('utf-8'))
        broadcast_to_usernames(chatroom.get('activeUsers'), response)

    elif message_data.get("method") == "get all":  # return all chatrooms of the user
        username = db.get_username_by_address(*addr)
        chatrooms = db.users.find_one({"username": username})  # returns user document containing only chatrooms property whichs is an array of objectId

        if chatrooms.get('chatrooms'):
            chatrooms = chatrooms["chatrooms"]
            # chatrooms = list(chatrooms["chatrooms"])
            # chatrooms= db.chatrooms.find([{"_id":ObjectId(chatroom)} for chatroom in chatrooms])      # iterate over the chatrooms which is array of ids
            chatrooms = db.chatrooms.find({"_id": {"$in": [ObjectId(chatroom) for chatroom in chatrooms]}})
            res = {
                'type': 'chatroom',
                'method': 'get all',
                'chatrooms': parse_json(list(chatrooms)),
            }
            send_to_client(conn, res)
        else:
            res = {
                'type': 'chatroom',
                'method': 'get all',
                'chatrooms': [],
            }
            send_to_client(conn, res)


# Function to handle 'HELLO' messages
def handle_hello(conn, addr):
    global last_hello_time
    try:
        if is_socket_open(conn):
            if conn in active_connections:
                username = db.get_username_by_address(*active_connections[conn])
                if username:
                    last_hello_time[username] = time.time()
    except Exception as e:
        print(f"Error in handle_hello: {e}")


def is_socket_open(sock):
    try:
        # This is a non-blocking call; it should return instantly no matter the state of the socket.
        # If the socket is open, it will not block. If it's closed, it will throw an exception.
        sock.getpeername()
        return True
    except:
        return False


def handle_get_online_users(conn):
    online_users = db.get_online_users()
    send_to_client(conn, {"type": "get_online_users_response", "users": online_users})


# Send a message to a single client
def send_to_client(conn, message):
    conn.send(json.dumps(message).encode('utf-8'))


def handle_user(conn, addr, message_data):
    username = db.users.find_one({"username": message_data.get("username")})
    res = {
        "type": "user",
        "method": "get",
        "user": parse_json(username),
    }
    send_to_client(conn, res)


# Handle client messages
def handle_client(conn, addr):
    # print(f"{addr} has connected.")
    send_to_client(conn, {"type": "welcome", "msg": "Connection established. Welcome to the P2P Chat Server!"})

    # Save the address information in the global dictionary

    while True:
        try:
            message = conn.recv(1024).decode('utf-8')
            if message:
                print(f"{addr}: {message}")
                message_data = json.loads(message)

                if message_data['type'] == 'get_online_users':
                    handle_get_online_users(conn)
                elif message_data['type'] == 'login':
                    handle_login(conn, message_data)
                elif message_data['type'] == 'create_account':
                    handle_create_account(conn, message_data)
                elif message_data['type'] == 'logout':
                    handle_logout(conn)
                elif message_data['type'] == 'exit':
                    handle_exit(conn)
                elif message_data['type'] == 'hello':
                    handle_hello(conn, addr)  # Handle 'HELLO' messages

                elif message_data['type'] == 'user':
                    handle_user(conn, addr, message_data)

                elif message_data['type'] == 'chatroom':
                    handle_chatroom(conn, addr, message_data)  # Handle 'HELLO' messages


        except ConnectionResetError as e:
            adress = active_connections[conn]
            adress = {'ip': adress[0], 'port': adress[1]}  # address : tuple

            handle_logout(conn)

        except Exception as e:
            if hasattr(e, 'characters_written'):
                print(f"Error: {e}\n{e.characters_written}")
            else:
                print(f"Error: {e}")
            break

    conn.close()


# Function to check and disconnect users who haven't sent a 'HELLO' message in 3 seconds
def check_and_disconnect_inactive_users():
    global last_hello_time
    while True:
        time.sleep(1)
        current_time = time.time()
        # Copy the dictionary to avoid changing size during iteration
        for username, last_time in last_hello_time.copy().items():
            if current_time - last_time > 3:
                # User hasn't sent a 'HELLO' message in 3 seconds, disconnect and remove entry
                address = db.get_address_by_username(username)
                if address:
                    conn = get_connection_by_address(address)
                    if conn:
                        handle_exit(conn)
                del last_hello_time[username]


def handle_login(conn, message_data):
    global is_logged_in
    username = message_data['username']
    password = message_data['password']
    login_success = db.verify_user_login(username, password)
    if login_success:
        db.user_login(username, *active_connections[conn], message_data["port"])  # Pass the IP and port
        send_to_client(conn, {"type": "login_response", "status": "ok", "msg": "Login successful."})
        print(f"User '{username}' logged in successfully.")
        is_logged_in = True
        # Update online users count
    else:
        send_to_client(conn, {"type": "login_response", "status": "error", "msg": "Invalid username or password."})
        print(f"User '{username}' attempted to login with invalid credentials.")


def handle_create_account(conn, message_data):
    # Handle account creation
    global is_logged_in
    username = message_data['username']
    password = message_data['password']
    account_creation_success = db.create_user_account(username, password)
    if account_creation_success:
        send_to_client(conn, {"type": "create_account_response", "status": "ok", "msg": "Account creation successful."})
        print(f"User '{username}' created an account successfully.")
        is_logged_in = True  # Set is_logged_in to True after successful account creation

    else:
        send_to_client(conn, {"type": "create_account_response", "status": "error", "msg": "Username already taken."})
        print(f"User '{username}' attempted to create an account, but the username is already taken.")


def handle_exit(conn):
    global is_logged_in
    username = db.get_username_by_address(*active_connections[conn])

    if username:
        if is_logged_in:
            db.user_logout(username)
            send_to_client(conn, {"type": "exit_response", "status": "ok", "msg": "Forced Logout because user exited."})
            print(f"User '{username}' exited successfully with forced Logout.")
        else:
            send_to_client(conn, {"type": "exit_response", "status": "ok", "msg": "Exit successful."})
            print(f"User '{username}' exited successfully.")

        # Remove the address entry
        del active_connections[conn]
        is_logged_in = False  # Set is_logged_in to False after successful logout
    else:
        send_to_client(conn, {"type": "exit_response", "status": "ok", "msg": "User not logged in and has exited."})
        print(f"An unauthenticated user at {active_connections[conn]} has exited.")
        # Remove the address entry
        del active_connections[conn]


def handle_logout(conn):
    # Handle user logout
    global is_logged_in
    username = db.get_username_by_address(*active_connections[conn])
    if username:
        db.user_logout(username)
        send_to_client(conn, {"type": "logout_response", "status": "ok", "msg": "Logout successful."})
        print(f"User '{username}' logged out successfully.")
        is_logged_in = False  # Set is_logged_in to False after successful logout
        handle_chatroom(conn, None, {"type": "chatroom", "method": "close", "username": username})
    else:
        send_to_client(conn, {"type": "logout_response", "status": "error", "msg": "User not logged in."})
        print(f"An unauthenticated user at {active_connections[conn]} attempted to logout.")


def main():
    print(f"Listening on {HOST}:{PORT_TCP}...")
    db.reset_online_users_count()

    check_thread = threading.Thread(
        target=check_and_disconnect_inactive_users)  # responsible for desconnecting inactive users
    check_thread.daemon = True
    check_thread.start()

    # Start the UDP thread
    udp_thread = threading.Thread(target=handle_hello_udp)
    udp_thread.daemon = True
    udp_thread.start()

    while True:
        client_conn, client_addr = server.accept()
        print(f"{client_addr} has connected.")

        # Store the connection along with its address
        active_connections[client_conn] = client_addr

        threading.Thread(target=handle_client, args=(client_conn, client_addr)).start()


# Start the server
if __name__ == "__main__":
    main()
