from pydantic import BaseModel


class PaymentsResponse(BaseModel):
    payments: list
    sub: str


class PaymentCreatedResponse(BaseModel):
    status: str
    sub: str
