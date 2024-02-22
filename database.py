import asyncio

import motor.motor_asyncio
from bson import ObjectId
from decouple import config
from fastapi import HTTPException
from motor.motor_asyncio import AsyncIOMotorCollection

from auth_utils import AuthJwtCsrf

MONGO_API_KEY = config("MONGO_API_KEY")

# Connect to the database
client = motor.motor_asyncio.AsyncIOMotorClient(MONGO_API_KEY)
client.get_io_loop = asyncio.get_event_loop

# database
db = client.API_DB
collection_todo = db.todo
collection_user = db.user

# Auth
auth = AuthJwtCsrf()

def todo_serializer(todo: AsyncIOMotorCollection) -> dict:
    """Serialize a todo from the database.

    Args:
        todo (AsyncIOMotorCollection): The todo to serialize.

    Returns:
        dict: The serialized todo.
    """
    return {
        "id": str(todo["_id"]),
        "title": todo["title"],
        "description": todo["description"]
    }


def user_serializer(user: AsyncIOMotorCollection) -> dict:
    """Serialize a user from the database.

    Args:
        user (AsyncIOMotorCollection): The user to serialize.

    Returns:
        dict: The serialized user.
    """
    return {
        "id": str(user["_id"]),
        "email": user["email"]
    }


async def db_create_todo(data: dict) -> dict | bool:
    """Create a new task.

    Args:
        data (dict): The data to create a task.

    Returns:
        dict | bool: The created task or False if the creation failed.
    """
    todo = await collection_todo.insert_one(data)
    new_todo = await collection_todo.find_one({"_id": todo.inserted_id})
    if new_todo is not None:
        return todo_serializer(new_todo)
    return False

async def db_get_todos() -> list:
    """Get all tasks.

    Returns:
        list: All tasks.
    """
    todos = []
    for todo in await collection_todo.find().to_list(length=100):
        todos.append(todo_serializer(todo))
    return todos

async def db_get_single_todo(id: str) -> dict | bool:
    """Get a task by ID.

    Args:
        id (str): The ID of the task to get.

    Returns:
        dict | bool: The task or False if the task doesn't exist.
    """
    todo = await collection_todo.find_one({"_id": ObjectId(id)})
    if todo is not None:
        return todo_serializer(todo)
    return False


async def db_update_todo(id: str, data: dict) -> dict | bool:
    """Update a task by ID.

    Args:
        id (str): The ID of the task to update.
        data (dict): The data to update the task with.

    Returns:
        dict | bool: The updated task or False if the update failed.
    """
    todo = await collection_todo.find_one({"_id": ObjectId(id)})
    if todo is not None:
        update_todo = await collection_todo.update_one(
            {"_id": ObjectId(id)}, {"$set": data}
        )

        if update_todo.matched_count > 0:
            new_todo = await collection_todo.find_one({"_id": ObjectId(id)})
            return todo_serializer(new_todo)
    return False


async def db_delete_todo(id: str) -> bool:
    """Delete a task by ID.

    Args:
        id (str): The ID of the task to delete.

    Returns:
        bool: True if the task was deleted, False if the task doesn't exist.
    """
    todo = await collection_todo.find_one({"_id": ObjectId(id)})
    if todo is not None:
        delete_todo = await collection_todo.delete_one({"_id": ObjectId(id)})

        if delete_todo.deleted_count > 0:
            return True
    return False


async def db_signup(data: dict) -> dict:
    """Sign up a new user.

    Args:
        data (dict): The data to sign up a new user.

    Raises:
        HTTPException: If the user already exists.
        HTTPException: If the password is too short.

    Returns:
        dict: The signed up user.
    """
    email = data.get("email")
    password = data.get("password")
    overlap_user = await collection_user.find_one({"email": email})

    if overlap_user is not None:
        raise HTTPException(status_code=401, detail="User already exists")
    if password is None or len(password) < 6:
        raise HTTPException(status_code=401, detail="Password is too short")

    hashed_password = auth.generate_hashed_pw(password)
    user = await collection_user.insert_one({"email": email, "password": hashed_password})
    new_user = await collection_user.find_one({"_id": user.inserted_id})
    return user_serializer(new_user)


async def db_login(data: dict) -> str:
    """Log in a user.

    Args:
        data (dict): The data to log in a user.

    Raises:
        HTTPException: If the user doesn't exist.
        HTTPException: If the password is invalid.

    Returns:
        str: The JWT token.
    """
    email = data.get("email")
    password = data.get("password")
    user = await collection_user.find_one({"email": email})

    if (
        user is None 
        or not auth.verify_password(password, user["password"])
    ):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = auth.encode_jwt(user["email"])
    return token
