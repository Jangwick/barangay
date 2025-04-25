# Barangay Management System

A web application for managing barangay operations including resident records, certificate issuance, announcements, blotter records, and basic healthcare/inventory management. Built with Flask and SQLAlchemy.

## Features

*   User Authentication & Role-Based Access Control (Admin, Doctor, Nurse, Staff)
*   Resident Management (Add, Edit, Delete)
*   Certificate Issuance & Printing (Clearance, Residency, etc.)
*   Announcements (Create, Edit, Delete)
*   Blotter Record Management (Add, Edit, Delete, View, Print)
*   Healthcare Module:
    *   Patient Registration
    *   Appointment Scheduling
    *   Medical Record Keeping
*   Inventory Tracking (Medicines, Supplies)
*   Audit Logging

## Setup

1.  **Clone the repository:**
    ```bash
    git clone <your-repository-url>
    cd barangay
    ```

2.  **Create a virtual environment:**
    ```bash
    python -m venv venv
    ```
    *   On Windows: `venv\Scripts\activate`
    *   On macOS/Linux: `source venv/bin/activate`

3.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```
    *(Note: You might need to create a `requirements.txt` file first using `pip freeze > requirements.txt` if one doesn't exist)*

4.  **(Optional) Set Secret Key:**
    For production, set the `SECRET_KEY` environment variable. For development, a default key is used in `app.py`.
    ```bash
    # Example (Linux/macOS)
    export SECRET_KEY='your-very-secret-key'
    # Example (Windows CMD)
    set SECRET_KEY=your-very-secret-key
    # Example (Windows PowerShell)
    $env:SECRET_KEY='your-very-secret-key'
    ```

## Running the Application

1.  **Activate the virtual environment** (if not already active).
2.  **Run the Flask development server:**
    ```bash
    flask run
    ```
    Or, if running `app.py` directly:
    ```bash
    python app.py
    ```
3.  Open your web browser and navigate to `http://127.0.0.1:5000` (or the address provided by Flask).

## Database

*   The application uses SQLite (`barangay.db`) by default.
*   The database file will be created automatically in the project directory when the application first runs.
*   Sample data (users, residents, etc.) will be added if the database is empty on the first run.

## Default Users

If the database is created for the first time, the following users are added:

*   **Username:** `admin`, **Password:** `admin123`, **Role:** Admin
*   **Username:** `doctor`, **Password:** `doctor123`, **Role:** Doctor
*   **Username:** `nurse`, **Password:** `nurse123`, **Role:** Nurse
*   **Username:** `staff`, **Password:** `staff123`, **Role:** Staff

## Technologies Used

*   **Backend:** Flask, SQLAlchemy, Flask-Login
*   **Frontend:** HTML, Tailwind CSS, Alpine.js
*   **Database:** SQLite (default)
