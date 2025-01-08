# from app.v1.utils.token import generate_jwt_token
from bson import ObjectId
from fastapi import HTTPException, Request, status

from app.v1.middleware.auth import get_current_user
from app.v1.models import support_collection
from app.v1.models.support import Support


class SupportManager:

    async def support_list(self, request: Request, token: str):
        try:
            current_user = await get_current_user(request=request, token=token)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

            if "admin" not in [role.value for role in current_user.roles]:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")

            support = await support_collection.find().to_list(None)
            if not support:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No support found")
            formatted_support = []
            for item in support:
                item["id"] = str(item.pop("_id", ""))
                formatted_support.append(item)
            return {"data": formatted_support}
        except Exception as ex:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))
