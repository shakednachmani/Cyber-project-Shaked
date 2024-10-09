 Web Application





## Prerequisites

Before setting up and running the application, ensure that you have the following installed:

- Python 3.x
- Flask
- SQLite (or any other database if you're using another DB)
- Virtual environment (optional but recommended)

## Setting Up the Application

### Step 1: Clone the Repository

Clone the repository from GitHub (or download the project files).

```bash
git clone <repository_url>
cd <project_directory>

Step 2: Install Dependencies
Create a virtual environment (optional but recommended) and install the required dependencies.

# Create and activate a virtual environment (optional)
python -m venv venv
source venv/bin/activate  # For Linux/Mac
venv\Scripts\activate     # For Windows

# Install required packages
pip install -r requirements.txt

Step 3: Create the Database
The first thing you need to do is to build the database.

Run the following script to create the necessary tables in the database.


python db.create.py

This will initialize the SQLite database and create the required tables, including the User and Clients tables.

Step 4: Run the Application
After setting up the database, you can now run the application.

python app.py

By default, Flask will start the application on http://127.0.0.1:5000/.

Step 5: Access the Application
Once the application is running, you can access it in your browser by navigating to:

http://127.0.0.1:5000/
