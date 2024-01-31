import pymongo
from pymongo import MongoClient
import hashlib
import os
from bson import ObjectId

USER_MASK = {"_id": 1, "username": 1, "online": 1, "address": 1}


class P2PChatDB:
    def __init__(self):
        # Connect to the MongoDB database server
        self.client = MongoClient('localhost', 27017)

        # Create or access the p2pchat database
        self.db = self.client['p2pchat']

        # Access the users collection
        self.users = self.db['users']

        self.chatrooms = self.db['chatrooms']

    def get_chatroom_by_id(self, chatroom_id):
        return self.chatrooms.find_one({"_id": ObjectId(chatroom_id)})

    def create_chatroom(self, users: list[str]) -> bool:
        try:
            chatroom = self.chatrooms.insert_one({"usernames": users, "activeUsers": []})
            chatroom = self.chatrooms.find_one({"_id": chatroom.inserted_id})
            for user in users:
                self.users.update_one({'username': user}, {
                    '$push': {'chatrooms': chatroom['_id']}})  # update the chatrooms of the user with the chatrooms id
            return chatroom
        except:
            return False

    def user_open_chatroom(self, chatroom_id: ObjectId,
                           user: str):  # update active users in chatroom with the user that opened the chatroom
        self.chatrooms.update_one({'_id': ObjectId(chatroom_id)}, {'$push': {'activeUsers': user}})

    def user_offline_chatroom(self, chatroom_id: ObjectId, user: str):  # update active users in chatroom by removing the user that went offline
        activeUsers = self.get_chatroom_by_id(ObjectId(chatroom_id))['activeUsers']
        activeUsers.remove(user)
        self.chatrooms.update_one({'_id': ObjectId(chatroom_id)}, {'$set': {'activeUsers': activeUsers}})

    def update_chatroom(self, chatroom_id, user: dict | str,
                        value: bool):  # value states whether the user accepted or rejected if True, then the user accepted to connect
        """
        params: user, is user object.
        value, is bool, True user wants to connect to the server.
        chatroom_id
        """
        if isinstance(user, str):  # if user is a string, get the user object from database
            user = self.users.find_one({"username": user})
        chatroom = self.chatrooms.find_one({"_id": ObjectId(chatroom_id)})
        if not value and user["username"] in chatroom[
            'usernames']:  # if user terminated connection and he is inside the chatroom remove him from the chatroom
            chatroom['usernames'].remove(user["username"])  # remove username from chatroom
            chatroom['activeUsers'].remove(user["username"])  # remove username from chatroom
            user["chatrooms"].remove(ObjectId(chatroom_id))
            self.users.update_one({"username": user["username"]}, {'$set': {'chatrooms': user[
                'chatrooms']}})  # update the chatrooms property with the modified user chatrooms property
            self.chatrooms.update_one({"_id": ObjectId(chatroom_id)}, {'$set': {'usernames': chatroom['usernames'],'activeUsers':chatroom['activeUsers']}})  # update the chatrooms property with the modified user chatrooms property

        elif value:  # user accepted the connection
            self.chatrooms.update_one({'_id': ObjectId(chatroom_id)}, {
                '$push': {'usernames': user["username"]}})  # insert the username that accepted to connect to the server
            self.users.update_one({"username": user["username"]}, {'$push': {
                'chatrooms': ObjectId(chatroom_id)}})  # update the chatrooms property with the modified user chatrooms property

        if len(chatroom['usernames']) == 0:
            self.delete_chatRoom( chatroom)
        # chatroom = self.chatrooms.update_one({"_id":chatroom_id},{})

    def delete_chatRoom(self, chatroom):
        for user in self.users.find({"usernames": {"$in": [user for user in chatroom[
            "usernames"]]}}):  # insert an array of usernames from the chatroom to remove from every user the chatroom id inside the chatrooms property
            user['chatrooms'].remove(chatroom.inserted_id)
            self.users.update_one({"username": user}, {'$set': {'chatrooms': user[
                'chatrooms']}})  # update the chatrooms property with the modified user chatrooms property
        self.chatrooms.delete_one(chatroom)

    def get_address_by_username(self, username: str) -> dict:
        """
        Get the address information for a user.

        Parameters:
        - username (str): The username of the user.

        Returns:
        dict: A dictionary containing address information.
            Example:
            { 'ip': '192.168.1.1', 'port': 5000 }
        """
        try:
            user = self.users.find_one({'username': username})
            if user and 'address' in user:
                return user['address']
            return None
        except Exception as e:
            print(f"Error getting address for user {username}: {e}")
            return None

    def checkPasswordExists(self, hashedPassword):
        for user in self.users.find():
            salt = bytes.fromhex(user['salt'])
            hashedPassword = hashlib.sha256(salt + hashedPassword.encode('utf-8')).hexdigest()
            if hashedPassword == user['password']:
                return True
        return False

    def create_user_account(self, username, password):
        # Check if username already exists

        if self.users.find_one({'username': username}) or self.checkPasswordExists(password):
            return False

        # Generate a new salt for this user
        salt = os.urandom(32)  # 32 bytes = 256 bits

        # Use the SHA-256 hash function
        hashed_pw = hashlib.sha256(salt + password.encode('utf-8')).hexdigest()

        # Create new user document
        user = {
            'username': username,
            'password': hashed_pw,
            'salt': salt.hex(),  # Store the salt as a hex string for retrieval
            'online': False,
            'address': None
        }

        # Insert new user into the database
        self.users.insert_one(user)
        return True

    def verify_user_login(self, username, password):
        # Find user by username
        user = self.users.find_one({'username': username})

        # Check if user exists
        if user:
            # Retrieve the stored salt for this user and convert it from hex to bytes
            # salt= hex(user['salt'])
            salt = bytes.fromhex(user['salt'])  # salt is random bytes generated then

            # Hash the provided password using the stored salt
            hashed_pw_attempt = hashlib.sha256(salt + password.encode('utf-8')).hexdigest()

            # Compare the hashed password with the stored hashed password
            if hashed_pw_attempt == user['password']:
                return True
        return False

    def user_login(self, username, ip, port, portRecv):
        """
        ip: is the ip of the user
        port: is the port of the user
        portRecv: is the port that the user is listening to
        """
        # Update user status to online and set last_login information
        self.users.update_one(
            {'username': username},
            {'$set': {'online': True, 'address': {'ip': ip, 'port': port, 'portRecv': portRecv}}}
        )

    def user_logout(self, username):
        # Update user status to offline and clear last_login information
        self.users.update_one(
            {'username': username},
            {'$set': {'online': False, 'address': None}}
        )

    def get_username_by_address(self, ip, port):
        # Find user by ip and port
        user = self.users.find_one({'address.ip': ip, 'address.port': port})
        if user:
            return user['username']
        return None

    def get_online_users(self):
        online_users = self.users.find({'online': True})
        return [user['username'] for user in online_users]

    # def update_online_users_count(self):
    #     online_users_count = self.users.count_documents({'online': True})
    #     self.users.update_many({}, {'$set': {'online_users_count': online_users_count}})

    def reset_online_users_count(self):
        # Reset the online status and count for all users
        self.users.update_many({}, {'$set': {'online': False}})
        self.chatrooms.update_many({}, {'$set': {'activeUsers': []}})
