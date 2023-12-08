# Microservice Deployment - Sneakers Expert Consultation

Tugas Besar II3160 - Teknologi Sistem Terintegrasi

Login and Register UI: <br/>
https://sneakersbandung.vercel.app/

API: <br/>
http://sneakersbandung.hzgecqhehxbtanhv.southeastasia.azurecontainer.io/docs

API Documentation:  
https://docs.google.com/document/d/1TTx1hG4iU3vlznPYn2uZIakj0IHSVdPwV_SvKl_C95c/edit?usp=sharing

Main Report Link: <br/>
https://docs.google.com/document/d/16V9IV-i7Wj2qDoAJBuZW76HF2ZgeBl4TBWbr5osXCIQ/edit?usp=sharing

# Deployment Steps:

## Install ODBC
Install ODBC to set connection string from Azure SQL Database Server [ODBC](https://go.microsoft.com/fwlink/?linkid=833576).

After that, input this code for connection string:
```python
Driver={ODBC Driver 18 for SQL Server};Server=tcp:mysqlserver18221074.database.windows.net,1433;Database=sneakersdb;Uid=azureuser;Pwd={your_password_here};Encrypt=yes;TrustServerCertificate=no;Connection Timeout=30;
```

## Create Virtual Environtment

```bash
python -m venv env
```

## Installation

Use the package manager [pip](https://pip.pypa.io/en/stable/) to install [FastAPI Uvicorn](https://fastapi.tiangolo.com/deployment/manually/)

```bash
pip install fastapi uvicorn
```

## Run Code

```python
uvicorn main:app --reload
```

## Using Docker in Local

Create Dockerfile:

```Docker
# Use a specific Python version
FROM python:3

# Set the working directory inside the container
WORKDIR /<folder_name>

# Copy only the requirements file to leverage Docker cache
COPY requirements.txt .

# Install any necessary dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the current directory contents into the container at /OAuthTSTFix
COPY . .

# Command to run the FastAPI server when the container starts
CMD ["uvicorn", "<file_name>:app", "--host", "0.0.0.0", "--port", "80"]

## Build Docker in Local
Run in CMD:
```Docker
docker build -t <image_name>:<tag> .
```

## Run Docker in Local
Run in CMD (if haven't created container yet)
```Docker
docker container run --publish <port>:<port> --name <container_name> <image_name>:<tag>
```

Run in CMD (if have already created container)
```Docker
docker run -p <port>:<port> <image_name>:<tag>
```

## Using Docker and Push Image to Azure Container Registry

Create Dockerfile:

```Docker
# Use a specific Python version
FROM python:3

# Set the working directory inside the container
WORKDIR /<folder_name>

# Install the Microsoft ODBC Driver for SQL Server
RUN curl https://packages.microsoft.com/keys/microsoft.asc | apt-key add - && \
    curl https://packages.microsoft.com/config/debian/10/prod.list > /etc/apt/sources.list.d/mssql-release.list && \
    apt-get update && \
    ACCEPT_EULA=Y apt-get install -y --no-install-recommends msodbcsql18 && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install FreeTDS and other required libraries for pyodbc
RUN apt-get update && \
    apt-get install -y --no-install-recommends unixodbc-dev freetds-bin freetds-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Copy only the requirements file to leverage Docker cache
COPY requirements.txt .

# Install any necessary dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the current directory contents into the container at /OAuthTSTFix
COPY . .

# Command to run the FastAPI server when the container starts
CMD ["uvicorn", "<file_name>:app", "--host", "0.0.0.0", "--port", "80"]
```

## Deploy in Microsoft Azure

1. Create [Azure Container Registry Service](https://azure.microsoft.com/en-us/products/container-registry)
2. Open this directory, Login to Azure Server Container Registry using Docker
```Docker
docker login <container_server> -u <container_username> -p <container_password>
```
3. Build Docker Image
```Docker
docker build -t <container_server>/<image_name>:<image_tag> .
```
4. Push Docker Image
```Docker
docker push <container_server>/<image_name>:<image_tag>
```
5. Create [Azure Container Instance](https://azure.microsoft.com/en-us/products/container-instances)

