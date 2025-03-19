# from app.v1.utils.token import generate_jwt_token
import pytz

from bson import ObjectId
from fastapi import HTTPException, Request, status

from app.v1.middleware.auth import get_current_user
from app.v1.models import support_collection
from app.v1.models.support import *


class SupportManager:

    async def support_list(
        self,
        request: Request,
        token: str,
        page: int,
        limit: int,
        search: str = None,
        statuss: str = None,
    ):
        try:
            current_user = await get_current_user(request=request, token=token)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

            if "admin" not in [role.value for role in current_user.roles] and current_user.user_role != 2:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page "
                )

            # Pagination variables
            skip = max((page - 1) * limit, 0)

            # Query to fetch all support data (or add filters as needed)
            query = {}  # Fetch all data

            if search:
                query["name"] = {"$regex": search, "$options": "i"}

            if statuss:
                query["status"] = statuss
            # Optionally, filter by specific fields
            # query = {"status": "active"}  # Example filter

            # Fetch the filtered and paginated support data
            support = await support_collection.find(query).skip(skip).limit(limit).to_list(None)

            if not support:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No support found")

            # Format the results
            formatted_support = []
            ist_timezone = pytz.timezone("Asia/Kolkata")
            for item in support:
                created_at = item.get("created_at")
                if isinstance(created_at, datetime):
                    created_at_utc = created_at.replace(tzinfo=pytz.utc)  # Assume UTC
                    created_at_ist = created_at_utc.astimezone(ist_timezone)  # Convert to IST
                    item["created_at"] = created_at_ist.isoformat()
                item["id"] = str(item.pop("_id", ""))
                formatted_support.append(item)

            # Get total count for pagination
            total_support = await support_collection.count_documents(query)
            total_pages = (total_support + limit - 1) // limit
            has_prev_page = page > 1
            has_next_page = page < total_pages
            prev_page = page - 1 if has_prev_page else None
            next_page = page + 1 if has_next_page else None
            return {
                "data": formatted_support,
                "paginator": {
                    "itemCount": total_support,
                    "perPage": limit,
                    "pageCount": total_pages,
                    "currentPage": page,
                    "slNo": skip + 1,
                    "hasPrevPage": has_prev_page,
                    "hasNextPage": has_next_page,
                    "prev": prev_page,
                    "next": next_page,
                },
            }
        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))

    async def support_detail(self, request: Request, token: str, support_id: str):
        try:
            current_user = await get_current_user(request=request, token=token)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

            if "admin" not in [role.value for role in current_user.roles] and current_user.user_role != 2:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page "
                )

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
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page "
                )

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
