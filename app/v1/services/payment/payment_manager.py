# from app.v1.utils.token import generate_jwt_token
import traceback

from typing import Any, Dict

from bson import ObjectId
from fastapi import HTTPException, Request, status

from app.v1.middleware.auth import get_current_user
from app.v1.models import payment_collection, transfer_amount_collection
from app.v1.models.payment import PaymentType
from app.v1.models.transfer_amount import TransferAmount
from app.v1.models.user import User


class PaymentManager:
    async def payment_type_list(
        self, request: Request, current_user: User, page: int, limit: int, search: str = None, statuss: str = None
    ):
        try:
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
            has_prev_page = page > 1
            has_next_page = page < total_pages
            prev_page = page - 1 if has_prev_page else None
            next_page = page + 1 if has_next_page else None
            return {
                "data": payment_data,
                "paginator": {
                    "itemCount": total_count,
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
            # return {"data": payment_data, "total_items": total_count, "total_pages": total_pages}
        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An unexpected error occurred"
            )

    async def update_payment(self, current_user: User, id: str, update_payment_request: PaymentType):
        try:
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

    async def get_transfer_amount(
        self, current_user: User, page: int, limit: int, search: str = None
    ) -> Dict[str, Any]:
        try:
            # Validate admin access
            if "admin" not in [role.value for role in current_user.roles] and current_user.user_role != 2:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="You do not have permission to access this page"
                )

            skip = max((page - 1) * limit, 0)
            query = {}
            if search:
                try:
                    search_value = float(search)
                    query["value"] = search_value
                except ValueError:
                    pass

            transfer_amounts = await TransferAmount.find(query).skip(skip).limit(limit).to_list(None)
            if not transfer_amounts:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND, detail="Transfer amount configuration not found"
                )

            transfer_data = []
            for transfer_amount in transfer_amounts:

                if not hasattr(transfer_amount, "value"):
                    raise HTTPException(
                        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                        detail="Transfer amount configuration is invalid",
                    )
                transfer_data.append(
                    {
                        "id": str(transfer_amount.id),
                        "value": transfer_amount.value,
                    }
                )

            total_count = await transfer_amount_collection.count_documents(query)
            total_pages = (total_count + limit - 1) // limit
            has_prev_page = page > 1
            has_next_page = page < total_pages
            prev_page = page - 1 if has_prev_page else None
            next_page = page + 1 if has_next_page else None

            return {
                "data": transfer_data,
                "paginator": {
                    "itemCount": total_count,
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

        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"An unexpected error occurred: {str(ex)}"
            )

    async def update_payment_value(self, current_user: User, transfer_amount: TransferAmount) -> Dict[str, Any]:
        try:
            if transfer_amount.value < 0 or transfer_amount.value > 100:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST, detail="Transfer amount value must be between 0 and 100"
                )

            existing_transfer_amount = await TransferAmount.find_one()

            if existing_transfer_amount:
                existing_transfer_amount.value = transfer_amount.value
                await existing_transfer_amount.save()
            else:
                new_transfer_amount = TransferAmount(value=transfer_amount.value)
                await new_transfer_amount.insert()

            return {
                "value": transfer_amount.value,
            }

        except HTTPException as e:
            raise e
        except Exception as ex:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"An unexpected error occurred: {str(ex)}"
            )
