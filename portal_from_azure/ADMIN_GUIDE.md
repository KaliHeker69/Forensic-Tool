# Admin User Management

## Overview
The Portal application now includes comprehensive admin user management capabilities. Administrators can add, delete, and manage user permissions.

## Default Admin User
- **Username**: `admin`
- **Password**: `admin123` (change this immediately in production!)
- **Email**: admin@portal.local

## Admin Capabilities

### 1. View All Users
```
GET /admin/users
```
Returns a list of all users in the system.

### 2. Add New User
```
POST /admin/users
Content-Type: application/json

{
  "username": "newuser",
  "password": "SecurePass123!",
  "email": "user@example.com",
  "full_name": "New User",
  "is_admin": false
}
```

### 3. Delete User
```
DELETE /admin/users/{username}
```
Deletes a user from the system. Admins cannot delete themselves.

### 4. Update User Information
```
PATCH /admin/users/{username}
Content-Type: application/json

{
  "email": "newemail@example.com",
  "full_name": "Updated Name",
  "disabled": false,
  "is_admin": false
}
```
All fields are optional. Only provided fields will be updated.

### 5. Grant Admin Access
```
POST /admin/users/{username}/make-admin
```
Promotes a user to admin status.

### 6. Revoke Admin Access
```
POST /admin/users/{username}/revoke-admin
```
Removes admin privileges from a user. Admins cannot revoke their own admin access.

## Security Features

- **Authorization Required**: All admin endpoints require authentication with admin privileges
- **Self-Protection**: Admins cannot delete themselves or revoke their own admin access
- **Password Hashing**: All passwords are securely hashed using bcrypt
- **JWT Tokens**: Secure token-based authentication

## Database Migration

If you have an existing database, run the migration script to add the `is_admin` column:

```bash
python migrate_db.py
```

This will:
1. Add the `is_admin` column to the users table
2. Set the default admin user's `is_admin` flag to `True`
3. Set all other existing users to `is_admin = False`

## API Documentation

Once the server is running, you can access the interactive API documentation at:
- **Swagger UI**: http://localhost:8000/api/docs
- **ReDoc**: http://localhost:8000/api/redoc

## Testing Admin Endpoints

### Using curl:

**Login to get token:**
```bash
curl -X POST "http://localhost:8000/auth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=admin123"
```

**List all users:**
```bash
curl -X GET "http://localhost:8000/admin/users" \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

**Create a new user:**
```bash
curl -X POST "http://localhost:8000/admin/users" \
  -H "Authorization: Bearer YOUR_TOKEN_HERE" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "password": "TestPass123!",
    "email": "test@example.com",
    "full_name": "Test User",
    "is_admin": false
  }'
```

**Grant admin access:**
```bash
curl -X POST "http://localhost:8000/admin/users/testuser/make-admin" \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

**Delete a user:**
```bash
curl -X DELETE "http://localhost:8000/admin/users/testuser" \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

## Error Responses

- **401 Unauthorized**: Not authenticated or invalid token
- **403 Forbidden**: Authenticated but not an admin
- **404 Not Found**: User not found
- **400 Bad Request**: Invalid request (e.g., trying to delete yourself)
- **500 Internal Server Error**: Server-side error

## Best Practices

1. **Change Default Password**: Immediately change the default admin password
2. **Limit Admin Users**: Only grant admin access to trusted users
3. **Regular Audits**: Periodically review the list of users and admins
4. **Strong Passwords**: Enforce strong password policies for all users
5. **HTTPS**: Always use HTTPS in production to protect credentials
