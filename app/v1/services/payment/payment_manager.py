# from app.v1.utils.token import generate_jwt_token
from bson import ObjectId
from fastapi import HTTPException, Request, status

from app.v1.middleware.auth import get_current_user
from app.v1.models import payment_collection
from app.v1.models.payment import PaymentType


class PaymentManager:
    async def payment_type_list(self, request: Request, token: str, page: int, limit: int, search: str = None,
                                statuss: str = None):
        try:
            # Get the current user
            current_user = await get_current_user(request=request, token=token)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

            # Check if the current user has the "vendor" role
            if "admin" not in [role.value for role in current_user.roles] and current_user.user_role != 2:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page "
                )
            skip = max((page - 1) * limit, 0)
            query = {}
            if search:
                search_regex = {"$regex": search, "$options": "i"}  # Case-insensitive search
                query["$or"] = [
                    {"name": search_regex},
                ]
            if statuss:
                query["status"] = statuss
            payment_types = await payment_collection.find(query).skip(skip).limit(limit).to_list(None)
            if not payment_types:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No payment types found")
            payment_data = []
            for payment in payment_types:
                payment_data.append(
                    {
                        "id": str(payment["_id"]),
                        "name": payment["name"],
                        "status": payment["status"],
                        "created_at": payment["created_at"],
                        "charge_type": payment["charge_type"],
                        "charge_value": payment["charge_value"],
                    }
                )
            total_count = await payment_collection.count_documents(query)
            total_pages = (total_count + limit - 1) // limit
            return {"data": payment_data, "total_items": total_count, "total_pages": total_pages}
        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An unexpected error occurred"
            )

    async def update_payment(self, request: Request, token: str, id: str, update_payment_request: PaymentType):
        try:
            # Get the current user
            current_user = await get_current_user(request=request, token=token)
            if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

            # Check if the current user has the "vendor" role
            if "admin" not in [role.value for role in current_user.roles] and current_user.user_role != 2:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page "
                )

            payment = await payment_collection.find_one({"_id": ObjectId(id)})
            if not payment:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Payment not found")
            update_data = {}
            if update_payment_request.status is not None:
                update_data["status"] = update_payment_request.status
            # if update_payment_request.charge_type not in ["percentage", "fixed"]:
            #     raise HTTPException(status_code=400, detail="Invalid charge type")
            # if update_payment_request.charge_value <= 0:
            #     raise HTTPException(status_code=400, detail="Charge value must be greater than 0")
            if update_payment_request.charge_type is not None:
                update_data["charge_type"] = update_payment_request.charge_type
            if update_payment_request.charge_value is not None:
                update_data["charge_value"] = update_payment_request.charge_value

            if not update_data:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST, detail="No valid fields provided for update"
                )
            # Update the payment
            await payment_collection.update_one({"_id": ObjectId(id)}, {"$set": update_data})

            update_payment = await payment_collection.find_one({"_id": ObjectId(id)})

            return {
                "id": str(update_payment["_id"]),
                "name": update_payment.get("name"),
                "status": update_payment.get("status"),
                "charge_type": update_payment.get("charge_type"),
                "charge_value": update_payment.get("charge_value"),
            }

        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An unexpected error occurred"
            )
