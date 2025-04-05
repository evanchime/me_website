# My Website

Welcome to my personal website repository! This project contains the source code for my personal website.

## Table of Contents

- [Introduction](#introduction)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Contributing](#contributing)
- [License](#license)

## Introduction

This website serves as my personal portfolio and blog. It showcases my projects, skills, and thoughts on various topics.

## Features

- Personal portfolio
- Different colour themes
- Login form
- Signup form
- Password change and reset 
- Blog and poll section
- Responsive design
- Search box that allows visitors to enter specific keywords or terms related to the site (Coming to you soon)
- Contact form that enables visitors to provide feedback or contact me (Coming to you soon)
- Subscribe to our newsletter form for monthly digest of what's new and exciting from us (Coming to you soon)
- Third party sign up (Coming to you soon)

## Installation

To run this project locally, follow these steps:

1. Clone the repository:
    ```
    git clone https://github.com/evanchime/me_website.git
    ```

2. Navigate to the project directory:
    ```
    cd me_website
    ```

3. Install a python virtual enviroment. Optional (recommended). Instruction is for Ubuntu. Proceed according to your enviroment
    ```
    sudo apt install python3-venv
    python3 -m venv my_env
    source my_env/bin/activate
    ```

    Remember to deactivate the environment when you're done:
    ```
    deactivate
    ```

4. Install the required dependencies:
    ```
    pip install -r requirements.txt
    ```

## Usage

### Prerequisites

#### Local Development (Without Docker)
- Database (SQLite by default; adjust for PostgreSQL/MySQL if needed)
- Create a .env file in the project root (use the template below in [ENVIRONMENT_VARIABLES](ENVIRONMENT_VARIABLES.md)).

#### Docker Development
- Docker Engine
- Docker Compose

### Local Development
1. After the [Installation](#installation) step, Create a .env file in the django project directory (use template [ENVIRONMENT_VARIABLES](ENVIRONMENT_VARIABLES.md))
2. Update .env with your settings (e.g., SECRET_KEY, DEBUG=True).
3. Change to the django project directory
4. Run migrations:
   ```
   python3 manage.py migrate
   ```
5. Start the development server:
   ```
   python3 manage.py runserver
   ```
6. Open your browser and go to `http://localhost:8000` to view the website.

### Docker Development
1. After the [Installation](#installation) step, Create a .env file in the project root(use template [ENVIRONMENT_VARIABLES](ENVIRONMENT_VARIABLES.md))
2. Update .env with your settings (e.g., SECRET_KEY, DEBUG=False).

#### Docker Compose

4. If using docker run, run the script in the project root:
   ```
   me_website_docker.sh
   ```
 

![First screenshot of me_website](screenshots/me_website_screenshot_1.png)
![Second screenshot of me_website](screenshots/me_website_screenshot_2.png)
![Third screenshot of me_website](screenshots/me_website_screenshot_3.png)
![Fourth screenshot of me_website](screenshots/me_website_screenshot_4.png)

## Contributing

Contributions are welcome! Please open an issue or submit a pull request if you have any improvements or bug fixes.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE.md) file for more details.