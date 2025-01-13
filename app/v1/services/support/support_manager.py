# from app.v1.utils.token import generate_jwt_token
from bson import ObjectId
from fastapi import HTTPException, Request, status

from app.v1.middleware.auth import get_current_user
from app.v1.models import support_collection
from app.v1.models.support import *


class SupportManager:

    async def support_list(self, request: Request, token: str, page: int, limit: int):
        try:
            current_user = await get_current_user(request=request, token=token)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

            if "admin" not in [role.value for role in current_user.roles] and current_user.user_role != 2:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")

            # Pagination variables
            skip = max((page - 1) * limit, 0)

            # Query to fetch all support data (or add filters as needed)
            query = {}  # Fetch all data

            # Optionally, filter by specific fields
            # query = {"status": "active"}  # Example filter

            # Fetch the filtered and paginated support data
            support = await support_collection.find(query).skip(skip).limit(limit).to_list(None)

            if not support:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No support found")

            # Format the results
            formatted_support = []
            for item in support:
                item["id"] = str(item.pop("_id", ""))
                formatted_support.append(item)

            # Get total count for pagination
            total_support = await support_collection.count_documents(query)
            total_pages = (total_support + limit - 1) // limit

            # Return the paginated data
            return {
                "data": formatted_support,
                "total_support": total_support,
                "total_pages": total_pages,
            }
        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))

    async def support_detail(self, request: Request, token: str, support_id: str):
        try:
            current_user = await get_current_user(request=request, token=token)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

            if "admin" not in [role.value for role in current_user.roles] and current_user.user_role != 2:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")

            support = await support_collection.find_one({"_id": ObjectId(support_id)})
            if not support:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No support found")
            support["id"] = str(support.pop("_id", ""))
            return support
        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))

    async def reply_support(self, request: Request, token: str, support_id: str, reply: str):
        try:
            # Verify the current user
            current_user = await get_current_user(request=request, token=token)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

            # Check if the user is an admin
            if "admin" not in [role.value for role in current_user.roles] and current_user.user_role != 2:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")

            # Fetch the support ticket
            support = await support_collection.find_one({"_id": ObjectId(support_id)})
            if not support:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Support ticket not found")

            # Update the reply and status
            updated_data = {
                "reply": reply,
            }
            await support_collection.update_one({"_id": ObjectId(support_id)}, {"$set": updated_data})

            # Fetch the updated ticket
            updated_support = await support_collection.find_one({"_id": ObjectId(support_id)})
            updated_support["id"] = str(updated_support.pop("_id"))

            return updated_support
        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))
