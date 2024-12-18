from fastapi import APIRouter, Depends, HTTPException, status
from app.v1.dependencies import get_user_manager
from app.v1.models import User
from app.v1.services import UserManager

router = APIRouter()


@router.post("/")
async def create_user(user: User, user_manager: UserManager = Depends(get_user_manager)) -> User:
    try:
        return await user_manager.create_user(user)  # Ensure this is awaited
    except ValueError as ex:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(ex))


@router.get("/{email}")
async def get_user(email: str, user_manager: UserManager = Depends(get_user_manager)) -> User:
    try:
        return await user_manager.get_user(email)  # Ensure this is awaited
    except ValueError as ex:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(ex))


@router.get("/")
async def list_users(user_manager: UserManager = Depends(get_user_manager)) -> list[User]:
    return await user_manager.list_users()  # Ensure this is awaited


@router.put("/{email}")
async def update_user(email: str, user: User, user_manager: UserManager = Depends(get_user_manager)) -> User:
    try:
        return await user_manager.update_user(email, user)  # Ensure this is awaited
    except ValueError as ex:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(ex))


@router.delete("/{email}")
async def delete_user(email: str, user_manager: UserManager = Depends(get_user_manager)) -> User:
    try:
        return await user_manager.delete_user(email)  # Ensure this is awaited
    except ValueError as ex:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(ex))
