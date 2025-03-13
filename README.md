# Dudas ETSIT

Dudas ETSIT is a web application developed in Flask to manage questions and discussions within a student group. It enables user authentication, voting, and commenting on various topics.

## Features
- **User authentication**: Register and log in.
- **Voting system**: Users can vote for the best answers and issues.
- **Messages and comments**: Users can post questions and respond to others.
- **Simple web interface** based on HTML and CSS.

## Installation
1. Clone this repository:
   ```bash
   git clone https://github.com/mario11gd/dudasETSIT.git
   cd dudasETSIT
   ```
2. Create and activate a virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows use: venv\Scripts\activate
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Load the groups into the database:
   ```bash
   python scripts/load_groups.py
   ```
5. Run the application:
   ```bash
   python app.py
   ```
6. Access the application at `http://127.0.0.1:5000/`

## Database Structure
The database structure is represented in the following diagram:

![alt text](database_structure/dudasETSIT.png)

## Project Structure
```
/
├── app.py              # Main application file
├── requirements.txt    # Project dependencies
├── static/             # Static files (images)
├── templates/          # HTML templates
├── database_structure/ # Database structure
├── instance/           # Database
└── scripts/            # Auxiliary scripts
```

## Contribution
If you want to contribute, fork the repository, create a branch with your changes, and submit a pull request.

## License
This project is distributed under the MIT license.