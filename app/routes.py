from datetime import datetime
import time
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from typing import List, Optional
from bson import ObjectId
from dotenv import load_dotenv
import os
import jwt
from app.auth import (
    create_access_token,
    get_password_hash,
    verify_access_token,
    pwd_context,
    oauth2_scheme,
)
from app.helpers import user_helper
from config.database import db
from .models import (
    LoginRequest,
    Order,
    OrderResponse,
    Product,
    User, 
    UserResponse
)

load_dotenv()

router = APIRouter()

@router.post("/register", response_model=UserResponse)
def register_user(user: User):
    """Register a new user."""
    user_dict = user.dict()
    
    if user.password:
        user_dict["password"] = get_password_hash(user.password)
    
    existing_user = db.users.find_one({"email": user_dict["email"]})
    if existing_user:
        raise HTTPException(status_code=400, detail={"detail": "Email already registered", "email": user_dict["email"]})

    user_dict["_id"] = ObjectId()
    try:
        result = db.users.insert_one(user_dict)
    except Exception as e:
        raise HTTPException(status_code=400, detail={"detail": "Error inserting user", "error": str(e)})

    created_user = db.users.find_one({"_id": result.inserted_id})
    if created_user is None:
        raise HTTPException(status_code=500, detail={"detail": "User creation failed"})

    return user_helper(created_user)

@router.post("/login")
def login_user(user: LoginRequest):
    """Authenticate user and provide access token."""
    db_user = db.users.find_one({"email": user.email})
    if not db_user or not pwd_context.verify(user.password, db_user["password"]):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"detail": "Invalid email or password", "email": user.email})
    
    access_token = create_access_token(data={"sub": db_user["email"]})
    return {"access_token": access_token, "token_type": "bearer"}

@router.get("/users/me", response_model=UserResponse)
def get_current_user(token: str = Depends(oauth2_scheme)):
    """Get current authenticated user's details."""
    email = verify_access_token(token)
    if email is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"detail": "Invalid authentication credentials", "token": token})
    
    user = db.users.find_one({"email": email})
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail={"detail": "User not found", "email": email})

    return user_helper(user)

@router.post("/products", response_model=Product)
def create_product(product: Product, token: str = Depends(oauth2_scheme)):
    """Create a new product in the database."""
    
    # Verify and decode the token to get the user information
    email = verify_access_token(token)  # Function to decode token and extract phone number
    if email is None:
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")

    # Retrieve the user based on the phone number
    user = db.users.find_one({"email": email})
    if user is None or user['role'] != "wholesaler":
        raise HTTPException(status_code=403, detail="You must be a wholesaler to create a product")

    # Prepare the product data
    product_dict = product.model_dump()
    product_dict['_id'] = ObjectId()

    # Convert the user to a dictionary using user_helper
    product_dict['wholesaler'] = user_helper(user).dict()  # Use .dict() to convert UserResponse to dict

    # Insert the product into the database
    try:
        result = db.products.insert_one(product_dict)
    except Exception as e:
        raise HTTPException(
            status_code=400, detail={"detail": "Error inserting product", "error": str(e)}
        )

    # Retrieve the newly created product
    created_product = db.products.find_one({"_id": result.inserted_id})
    if created_product is None:
        raise HTTPException(status_code=500, detail="Product creation failed")

    # Return the product data, ensuring the wholesaler is formatted correctly
    created_product['wholesaler'] = user_helper(user).dict()  # Ensure to send back only safe user data
    return created_product

@router.delete("/products/{product_id}", response_description="Delete a product")
def delete_product(product_id: str, token: str = Depends(oauth2_scheme)):
    """Delete a product by ID, only if the user is the wholesaler."""
    
    # Verify and decode the token to get the user information
    email = verify_access_token(token)
    if email is None:
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")

    # Retrieve the user based on the email
    user = db.users.find_one({"email": email})
    if user is None or user['role'] != "wholesaler":
        raise HTTPException(status_code=403, detail="You must be a wholesaler to delete a product")

    # Retrieve the product from the database
    product = db.products.find_one({"_id": ObjectId(product_id)})
    if product is None:
        raise HTTPException(status_code=404, detail={"detail": "Product not found", "product_id": product_id})

    # Check if the user is the wholesaler of the product
    if product['wholesaler']['email'] != email:
        raise HTTPException(status_code=403, detail="You are not authorized to delete this product")

    # Attempt to delete the product from the database
    result = db.products.delete_one({"_id": ObjectId(product_id)})
    
    if result.deleted_count == 1:
        return {"detail": "Product deleted successfully."}
    else:
        raise HTTPException(status_code=404, detail={"detail": "Product not found", "product_id": product_id})

@router.get("/products/{product_id}", response_description="Get a product")
def get_product(product_id: str, token: str = Depends(oauth2_scheme)):
    """Get a product by ID, only if the user is the wholesaler."""
    
    # Verify and decode the token to get the user information
    email = verify_access_token(token)
    if email is None:
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")

    # Retrieve the user based on the email
    user = db.users.find_one({"email": email})
    if user is None:
        raise HTTPException(status_code=403, detail="You must register or login to access this product")

    # Retrieve the product from the database
    product = db.products.find_one({"_id": ObjectId(product_id)})
    if product is None:
        raise HTTPException(status_code=404, detail={"detail": "Product not found", "product_id": product_id})

    # Convert the ObjectId to string before returning the product
    product["_id"] = str(product["_id"])

    # Return the product data
    return product

@router.get("/products/category/{category}", response_model=List[Product])
def get_products_by_category(category: str, token: str = Depends(oauth2_scheme)):
    """Retrieve products by category."""
    
    # Verify and decode the token to ensure the user is authenticated
    email = verify_access_token(token)
    if email is None:
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")

    # Retrieve products in the specified category
    products = list(db.products.find({"category": category}))

    if not products:
        raise HTTPException(status_code=404, detail={"detail": "No products found in this category", "category": category})

    return [Product(**product) for product in products]  # Return a list of product responses
    
@router.get("/products", response_model=List[Product])
def get_all_products(token: str = Depends(oauth2_scheme)):
    """Retrieve all products."""
    
    # Verify and decode the token to ensure the user is authenticated
    email = verify_access_token(token)
    if email is None:
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")

    # Retrieve all products
    products = list(db.products.find())
    
    if not products:
        raise HTTPException(status_code=404, detail={"detail": "No products found"})

    # Convert ObjectId to string and include it in the response
    for product in products:
        product["id"] = str(product["_id"])  # Convert _id to string
        product.pop("_id")  # Remove the ObjectId field to avoid passing it to the response model

    return [Product(**product) for product in products]  # Return a list of product responses

@router.get("/products/search", response_model=List[Product])
def search_products(query: Optional[str] = None, token: str = Depends(oauth2_scheme)):
    """Search for products by name or description."""
    
    # Verify and decode the token to ensure the user is authenticated
    email = verify_access_token(token)
    if email is None:
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")

    # Create a search filter based on the query
    search_filter = {}
    if query:
        search_filter["$or"] = [
            {"name": {"$regex": query, "$options": "i"}},  # Search by name
            {"description": {"$regex": query, "$options": "i"}}  # Search by description
        ]
    
    # Retrieve products matching the search filter
    products = list(db.products.find(search_filter))

    if not products:
        raise HTTPException(status_code=404, detail={"detail": "No products found matching the search criteria"})

    return [Product(**product) for product in products]  # Return a list of product responses

@router.post("/orders", response_model=OrderResponse)
def create_order(order: Order, token: str = Depends(oauth2_scheme)):
    """Create a new order."""

    # Verify and decode the token to get the user information
    email = verify_access_token(token)
    if email is None:
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")

    # Retrieve the retailer based on the email
    retailer = db.users.find_one({"email": email})
    if retailer is None or retailer['role'] != "retailer":
        raise HTTPException(status_code=403, detail="You must be a retailer to create an order")

    # Prepare the order data
    order_dict = order.model_dump()
    order_dict["_id"] = ObjectId()  # Use _id to match MongoDB convention
    order_dict['retailer'] = user_helper(retailer).model_dump()  # Add retailer info

    # Insert the order into the database
    try:
        result = db.orders.insert_one(order_dict)
    except Exception as e:
        raise HTTPException(status_code=400, detail={"detail": "Error inserting order", "error": str(e)})

    # Retrieve the newly created order
    created_order = db.orders.find_one({"_id": result.inserted_id})
    if created_order is None:
        raise HTTPException(status_code=500, detail="Order creation failed")

    # Convert ObjectId to string before returning
    created_order["id"] = str(created_order["_id"])  # Convert _id to string
    created_order.pop("_id")  # Remove the ObjectId field to avoid passing it to the response model

    return OrderResponse(**created_order)  # Return the order response


@router.get("/orders", response_model=List[OrderResponse])
def get_orders(token: str = Depends(oauth2_scheme)):
    """Retrieve all orders for the authenticated retailer."""

    # Verify the token to ensure the user is authenticated
    email = verify_access_token(token)
    if email is None:
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")

    # Retrieve the retailer based on the email
    retailer = db.users.find_one({"email": email})
    if retailer is None or retailer['role'] != "retailer":
        raise HTTPException(status_code=403, detail="You must be a retailer to retrieve orders")

    # Filter orders based on the retailer's ID or email
    orders = list(db.orders.find({"retailer.email": email}))  # Assuming retailer info is stored in orders

    # Convert ObjectId to string for response
    for order in orders:
        order["id"] = str(order["_id"])  # Convert _id to string
        order.pop("_id")  # Remove the ObjectId field to avoid passing it to the response model

    return [OrderResponse(**order) for order in orders]  # Return a list of order responses

@router.get("/orders/{order_id}", response_model=OrderResponse)
def get_order(order_id: str, token: str = Depends(oauth2_scheme)):
    """Retrieve a specific order by ID."""
    
    # Verify the token to ensure the user is authenticated
    email = verify_access_token(token)
    if email is None:
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")

    # Retrieve the order from the database
    order = db.orders.find_one({"_id": ObjectId(order_id)})
    if order is None:
        raise HTTPException(status_code=404, detail={"detail": "Order not found", "order_id": order_id})

    return OrderResponse(**order)  # Return the order response

@router.put("/orders/{order_id}", response_model=OrderResponse)
def update_order(order_id: str, order: Order, token: str = Depends(oauth2_scheme)):
    """Update an existing order by ID."""
    
    # Verify the token to ensure the user is authenticated
    email = verify_access_token(token)
    if email is None:
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")

    # Retrieve the order from the database
    existing_order = db.orders.find_one({"_id": ObjectId(order_id)})
    if existing_order is None:
        raise HTTPException(status_code=404, detail={"detail": "Order not found", "order_id": order_id})

    # Update the order fields
    updated_order_dict = order.model_dump()
    updated_order_dict['updated_at'] = datetime.utcnow()  # Update timestamp

    # Update the order in the database
    try:
        db.orders.update_one({"_id": ObjectId(order_id)}, {"$set": updated_order_dict})
    except Exception as e:
        raise HTTPException(status_code=400, detail={"detail": "Error updating order", "error": str(e)})

    # Retrieve the updated order
    updated_order = db.orders.find_one({"_id": ObjectId(order_id)})
    return OrderResponse(**updated_order)  # Return the updated order response

@router.delete("/orders/{order_id}", response_description="Delete an order")
def delete_order(order_id: str, token: str = Depends(oauth2_scheme)):
    """Delete an order by ID."""
    
    # Verify the token to ensure the user is authenticated
    email = verify_access_token(token)
    if email is None:
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")

    # Retrieve the order from the database
    order = db.orders.find_one({"_id": ObjectId(order_id)})
    if order is None:
        raise HTTPException(status_code=404, detail={"detail": "Order not found", "order_id": order_id})

    # Attempt to delete the order from the database
    result = db.orders.delete_one({"_id": ObjectId(order_id)})
    
    if result.deleted_count == 1:
        return {"detail": "Order deleted successfully."}
    else:
        raise HTTPException(status_code=404, detail={"detail": "Order not found", "order_id": order_id})
