from typing import Optional, List
from datetime import datetime
from enum import Enum
from pydantic import BaseModel, EmailStr, Field
from bson import ObjectId

# Enum for the user role
class UserRole(str, Enum):
    wholesaler = "wholesaler"
    retailer = "retailer"
    admin = "admin"

# Enum for Order Status
class OrderStatus(str, Enum):
    pending = "pending"
    processing = "processing"
    completed = "completed"
    canceled = "canceled"

# Enum for Payment Status
class PaymentStatus(str, Enum):
    pending = "pending"
    paid = "paid"
    failed = "failed"

# Login request model
class LoginRequest(BaseModel):
    email: EmailStr  # User's email for login
    password: str  # Password for login

# User model matching the Laravel schema
class User(BaseModel):
    name: str  # User's name
    email: EmailStr  # Unique email field
    password: str  # Hashed password field
    role: UserRole  # Enum for role: 'wholesaler', 'retailer', 'admin'
    phone_number: str  # User's phone number
    address: str  # Text field for the user's address
    profile_image: Optional[str] = None  # Optional profile image path
    company_name: Optional[str] = None  # Optional company name
    created_at: datetime = Field(default_factory=datetime.now)  # Auto-generated creation timestamp
    updated_at: datetime = Field(default_factory=datetime.now)  # Auto-generated update timestamp

    class Config:
        from_attributes = True  # Enables ORM compatibility for reading from databases

# User response model
class UserResponse(BaseModel):
    name: str
    email: str
    role: str
    phone_number: str
    address: str
    profile_image: Optional[str] = None
    company_name: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

# Product model
class Product(BaseModel):
    id: str  # Field for MongoDB ObjectId, represented as a string
    wholesaler: Optional[UserResponse] = None
    name: str
    description: str
    price: float = Field(..., gt=0)  # Price field with validation for being greater than zero
    stock_quantity: int
    category: str
    image: Optional[str] = None  # Image is optional
    created_at: Optional[datetime] = Field(default_factory=datetime.utcnow)
    updated_at: Optional[datetime] = Field(default_factory=datetime.utcnow)

    class Config:
        from_attributes = True  # This allows using this model with MongoDB
        json_encoders = {
            ObjectId: str,  # Ensure ObjectId is serialized as a string
        }

# Order model
class Order(BaseModel):
    retailer: Optional[UserResponse] = None  # Retailer information
    products: List  # List of products in the order
    total_amount: float = Field(..., gt=0)  # Total order amount, must be greater than 0
    status: OrderStatus  # Enum for order status
    payment_status: PaymentStatus  # Enum for payment status
    payment_method: str  # Payment method used for the order
    created_at: Optional[datetime] = Field(default_factory=datetime.utcnow)  # Order creation timestamp
    updated_at: Optional[datetime] = Field(default_factory=datetime.utcnow)  # Order update timestamp

    class Config:
        from_attributes = True  # Enables ORM compatibility for reading from databases

# Order response model
class OrderResponse(Order):
    id: str

    class Config:
        from_attributes = True
