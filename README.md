## Flask User Management API

This project is a **User Management API** built with **Flask**, **MongoDB**, and **PyMongo**. It provides CRUD operations for managing users, along with authentication. The project includes a Swagger UI for API documentation and testing.

### Features

- Create a new user
- Get all users
- Get a user by ID
- Update a user by ID
- Delete a user by ID
- User authentication (login)
- MongoDB integration
- Swagger UI for API documentation

### User Schema

- `username`: (string) User's email in the format `username@pbus.com`
- `password`: (string) Hashed password
- `role`: (string) Role of the user - can be `user`, `admin`, `expert`, or `virtual assistant`
- `active`: (boolean) Status of the user - `True` or `False`
- `department`: (string) The department of the user
- `domain`: (string) The domain the user belongs to
- `created_at`: (ISO timestamp) User creation date
- `updated_at`: (ISO timestamp) Last update date

### Prerequisites

Before running the project, ensure you have the following installed:

- **Python 3.7+**
- **MongoDB** (running locally or using a MongoDB cloud instance)
- **pip** (Python package installer)

### Installation

1. **Clone the repository**

   ```bash
   git clone https://github.com/bhanu-code-repo/user-mgmt-api
   cd flask-user-management-api
   ```

2. **Create a virtual environment**

   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**

   ```bash
   pip install -r requirements.txt
   ```

4. **Set up MongoDB**

   Make sure MongoDB is running on your local machine or use a MongoDB Atlas cloud instance. Add the MongoDB connection string to your environment as follows:

   ```bash
   export MONGO_URI="mongodb://localhost:27017/yourdbname"  # For Linux/macOS
   ```

   On Windows, use:

   ```bash
   set MONGO_URI="mongodb://localhost:27017/yourdbname"
   ```

### Running the Application

1. **Start the Flask app**

   ```bash
   python app.py
   ```

2. Open your browser and go to `http://localhost:5000/apidocs/` to view the Swagger UI for API documentation and testing.

---

### API Endpoints

| Method | Endpoint      | Description               | Auth Required |
| ------ | ------------- | ------------------------- | ------------- |
| POST   | `/users`      | Create a new user         | No            |
| GET    | `/users`      | Get a list of all users   | No            |
| GET    | `/users/<id>` | Get user by ID            | No            |
| PUT    | `/users/<id>` | Update user by ID         | No            |
| DELETE | `/users/<id>` | Delete user by ID         | No            |
| POST   | `/login`      | Authenticate user (login) | No            |

---
