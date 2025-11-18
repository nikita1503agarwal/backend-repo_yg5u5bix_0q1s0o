"""
Database Schemas for CodeGummies

Each Pydantic model maps to a MongoDB collection with the lowercase class name.
Required collections:
- users
- admins
- team_members
- sessions
- blog_posts
- services

These schemas are used for validation and documentation.
"""
from typing import Optional, List
from pydantic import BaseModel, Field, EmailStr
from datetime import datetime

# Users (regular)
class User(BaseModel):
    name: str = Field(..., description="Full name")
    email: EmailStr = Field(..., description="Unique email address")
    password_hash: Optional[str] = Field(None, description="BCrypt password hash (server-side only)")
    provider: str = Field("local", description="Auth provider: local | google")
    email_verified: bool = Field(False, description="Whether user's email is verified")
    role: str = Field("user", description="Role: user")
    avatar_url: Optional[str] = None

# Admins (pre-seeded; no signup route)
class Admin(BaseModel):
    name: str
    email: EmailStr
    password_hash: str
    role: str = Field("admin", description="Role: admin")

# Team members (managed by admins)
class TeamMember(BaseModel):
    name: str
    title: str
    photo_url: Optional[str] = None
    bio: Optional[str] = None
    active: bool = True

# Sessions (JWT metadata)
class Session(BaseModel):
    user_id: str
    role: str
    user_agent: Optional[str] = None
    ip: Optional[str] = None
    expires_at: Optional[datetime] = None

# Blog posts
class BlogPost(BaseModel):
    title: str
    slug: str
    excerpt: Optional[str] = None
    content: str
    author_id: Optional[str] = None
    tags: Optional[List[str]] = None
    published: bool = False
    published_at: Optional[datetime] = None

# Services
class Service(BaseModel):
    title: str
    slug: str
    description: str
    features: Optional[List[str]] = None
    icon: Optional[str] = None
    active: bool = True
