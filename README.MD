# Assignment Portal API

## Overview

The **Assignment Portal API** is a backend application built using **FastAPI** for managing assignments, user authentication, and user roles (Admin/User). It supports registration, login, assignment upload, and role-based access for users and admins. Admins can accept or reject assignments, and users can upload tasks to be reviewed by admins.

## Features

- **User Authentication:**

  - Secure registration and login using hashed passwords (bcrypt).
  - OAuth2-based token authentication for accessing protected routes.
- **User Management:**

  - Role-based access control (admin and user roles).
- **Assignment Management:**

  - Users can upload assignments with a timestamp.
  - Admins can accept or reject assignments.
- **JWT Token Authentication:**

  - Access tokens are created using JWT and passed in the `Authorization` header as a Bearer token.

## Tech Stack

- **Backend Framework:** FastAPI
- **Database:** MongoDB
- **Authentication:** OAuth2 + JWT
- **Password Hashing:** bcrypt via PassLib
- **Environment Management:** Python with virtual environment

## Prerequisites

- Python 3.7+
- MongoDB instance (local or cloud)
- Install dependencies using the `requirements.txt`

## Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/yourusername/assignment-portal.git
  ```

2. Change to the folder:
  ```bash
   cd assignment-portal
  ```

3. Install the python modules in the requirements.txt file:
  ```bash
   pip install -r requirements.txt
  ```

4. Run the API using Uvicorn:
  ```bash
   uvicorn main:app --reload
   ```
