# Running Script to build and run servers

## Prerequisites

Ensure that you have Docker and Docker Compose installed on your system. If not, you can download and install them from the official Docker website:

- [Docker Installation Guide](https://docs.docker.com/get-docker/)
- [Docker Compose Installation Guide](https://docs.docker.com/compose/install/)

## Running the Application with Docker Compose

To run the application using Docker Compose with the `-d` (detached) option, follow these steps:

1. **Clone the Repository:**
    ```bash
    git clone https://github.com/tjfernandes/SRSC_TP2.git
    cd SRSC_TP2
    ```

2. **Review the `docker-compose.yml` File:**
   Open the `docker-compose.yml` file in a text editor to review the services, configurations, and any environment variables specified.

3. **Build and Run Servers:**
   Execute the following command to execute the script that builds the servers and execute the dockerc-compose.yml file that creates the containers for the servers.
    ```bash
    /bin/bash build_and_run.sh
    ```
