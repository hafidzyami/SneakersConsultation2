from datetime import datetime, timedelta
from typing import Annotated
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from typing import List
import pyodbc


# Azure SQL
server = 'mysqlserver18221074.database.windows.net,1433'
database = 'sneakersdb'
username = '.....'
password = '.....'
driver = '{ODBC Driver 18 for SQL Server}'
connection_string = f'DRIVER={driver};SERVER={server};DATABASE={database};Uid={username};Pwd={password};Encrypt=yes;TrustServerCertificate=no;Connection Timeout=30;Login Timeout=60;'

def create_connection():
    return pyodbc.connect(connection_string)

connection = create_connection()

# to get a string like this run:
# openssl rand -hex 32
SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: str | None = None

class UserLogin(BaseModel):
    username: str
    is_admin: bool | None = None

class UserInDB(UserLogin):
    is_admin : bool
    hashed_password: str
    
class RegisterData(BaseModel):
    username: str
    password : str
    
class UserData(BaseModel):
    age : int
    footsize : int
    category : str
    budget : int
    
class SneakersDetails(BaseModel):
    size: int
    stock: int
    price: int
    
class Sneakers(BaseModel):
    id: int
    name: str
    category:str
    details : List[SneakersDetails]
    

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def get_user(username: str):
    try:
        with connection.cursor() as cursor:
            cursor.execute(f"SELECT * FROM users_login WHERE username = ?", username)
            row = cursor.fetchone()
        if row:
            user_dict = {
                "username": row.username,
                "hashed_password": row.hashed_password,
                "is_admin": row.is_admin
            }
            return UserInDB(**user_dict)
        return None
    finally:
        # connection.close()
        print('done')


def authenticate_user(username: str, password: str):
    user = get_user(username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user(username=token_data.username)
    if user is None:
        raise credentials_exception
    return user

async def get_current_admin(
    current_user: Annotated[UserLogin, Depends(get_current_user)]
):
    if not current_user.is_admin:
        raise HTTPException(status_code=400, detail="This Method is Accessible only for Admin, not Basic User!")
    return current_user

async def get_current_basic_user(
    current_user: Annotated[UserLogin, Depends(get_current_user)]
):
    if current_user.is_admin:
        raise HTTPException(status_code=400, detail="This Method is Accessible only for Basic User, not Admin!")
    return current_user

@app.post("/register", tags=['Register'])
async def register_user(data : RegisterData):
    
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1 FROM users_login WHERE username = ?", data.username)
            if cursor.fetchone():
                raise HTTPException(status_code=400, detail="Username already taken")

            # Hash the password before saving it to the database
            hashed_password = pwd_context.hash(data.password)
            cursor.execute("SELECT id FROM users_login ORDER BY id DESC")
            count = int(cursor.fetchone()[0])

            # Insert the user data into the users_login table
            cursor.execute("""
                INSERT INTO users_login (id, username, hashed_password, is_admin)
                VALUES (?, ?, ?, 0)
            """, count+1, data.username, hashed_password)
            
            cursor.execute("SELECT id FROM users ORDER BY id DESC")
            countUsers = int(cursor.fetchone()[0])

            cursor.execute("""
                INSERT INTO users (id, age, footsize, category, budget, username)
                VALUES (?, null, null, null, null, ?)
            """, countUsers+1, data.username)         
            

            # Commit the transaction
            connection.commit()
            return {"message": "User registered successfully"}
    finally:
        # connection.close()
        print('done')
    

@app.post("/token", response_model=Token, tags = ['Generate Token'])
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()]
):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/details/me", tags=['Auth Users', 'Admin'])
async def read_my_details(
    current_user: Annotated[UserLogin, Depends(get_current_user)]
):
    try:
        with connection.cursor() as cursor:
            if(current_user.username != 'admin'):
                cursor.execute("SELECT id, username, age, footsize, category, budget FROM users WHERE username=?", (current_user.username))
                user = cursor.fetchone()
                return {
                    'id': user[0],
                    'username' : user[1],
                    'age': user[2],
                    'footsize': user[3],
                    'category' : user[4],
                    'budget' : user[5]
                }
            else:
                return{
                    'username' : 'admin',
                    'is_admin' : True
                }
    finally:
        # connection.close()
        print('done')
    
@app.put("/update/me", tags=['Auth Users'])
async def update_my_data(
    current_user: Annotated[UserLogin, Depends(get_current_basic_user)],
    data : UserData
):
    
    try:
        with connection.cursor() as cursor:
            cursor.execute("UPDATE users SET age=?, footsize=?, category=?, budget=? WHERE username=?",
                           (data.age, data.footsize, data.category, data.budget, current_user.username))
            connection.commit()
            return "updated"
    finally:
        # connection.close()
        print('done')

@app.get('/sneakers', tags=['All Can Access'])
async def read_all_sneakers():
    
    try:
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT s.id, s.name, s.category, sd.sneakersize, sd.stock, sd.price
                FROM sneakers s
                JOIN sneaker_details sd ON s.id = sd.sneaker_id
                ORDER BY s.id
            """)
            sneaker_data = cursor.fetchall()

        sneakers_list = []
        current_sneaker_id = None
        current_sneaker_details = []

        for item in sneaker_data:
            if item[0] != current_sneaker_id:
                if current_sneaker_id is not None:
                    sneakers_list.append({
                        'id': current_sneaker_id,
                        'name': current_sneaker_name,
                        'category': current_sneaker_category,
                        'details': current_sneaker_details
                    })

                current_sneaker_id = item[0]
                current_sneaker_name = item[1]
                current_sneaker_category = item[2]
                current_sneaker_details = []

            current_sneaker_details.append({
                'size': item[3],
                'stock': item[4],
                'price': item[5]
            })

        if current_sneaker_id is not None:
            sneakers_list.append({
                'id': current_sneaker_id,
                'name': current_sneaker_name,
                'category': current_sneaker_category,
                'details': current_sneaker_details
            })

        return sneakers_list

    finally:
        # connection.close()
        print('done')
        
@app.get('/sneakers/{sneaker_id}', tags=['All Can Access'])
async def read_sneaker(sneaker_id: int):
    
    try:
        with connection.cursor() as cursor:
            # Fetch sneaker information
            cursor.execute(f"SELECT id, name, category FROM sneakers WHERE id={sneaker_id}")
            sneaker_info = cursor.fetchone()

            if not sneaker_info:
                raise HTTPException(
                    status_code=404, detail=f'Sneaker with id {sneaker_id} not found'
                )
            # Fetch sneaker details
            cursor.execute(f"SELECT sneakersize, stock, price FROM sneaker_details WHERE sneaker_id={sneaker_id}")
            details_data = cursor.fetchall()

        details_list = [{"size": size, "stock": stock, "price": price} for size, stock, price in details_data]

        sneaker = {
            "id": sneaker_info[0],
            "name": sneaker_info[1],
            "details": details_list,
            "category": sneaker_info[2]
        }

        return sneaker

    finally:
        # connection.close()
        print('done')
        

@app.post('/doconsult/me', tags=['Auth Users'])
async def do_consult(
    current_user: Annotated[UserLogin, Depends(get_current_basic_user)]
):
    try:
        with connection.cursor() as cursor:
            # Check if the user exists
            cursor.execute("SELECT * FROM users WHERE username=?", (current_user.username,))
            user = cursor.fetchone()

            count = 0
            sneakers_id = 0
            notes = 'Sneakers alternatif: '
            sneakers_name = ''
            

            # Find suitable sneakers
            cursor.execute("SELECT s.id, s.name, s.category, sd.sneakersize, sd.price FROM sneakers s "
                           "JOIN sneaker_details sd ON s.id = sd.sneaker_id "
                           "WHERE s.category = ? AND sd.sneakersize = ? AND sd.price <= ?",
                           (user.category, user.footsize, user.budget))
            sneakers_data = cursor.fetchall()

            for sneaker in sneakers_data:
                count += 1
                if count >= 2:
                    notes += f"{sneaker.name} (id: {sneaker.id}), "
                else:
                    sneakers_id += sneaker.id
                    sneakers_name += sneaker.name

            if count == 0:
                consult_data = {
                    "user_id": user.id,
                    "username" : current_user.username,
                    "sneaker_id": None,
                    "sneaker_name": None,
                    "consult_notes": "Tidak ada sneakers yang cocok dari segi size, category, ataupun budget Anda"
                }
            elif count == 1:
                consult_data = {
                    "user_id": user.id,
                    "username" : current_user.username,
                    "sneaker_id": sneakers_id,
                    "sneaker_name": sneakers_name,
                    "consult_notes": "Tidak ada sneakers lain yang menjadi alternatif"
                }
            else:
                consult_data = {
                    "user_id": user.id,
                    "username" : current_user.username,
                    "sneaker_id": sneakers_id,
                    "sneaker_name": sneakers_name,
                    "consult_notes": notes
                }
                
            cursor.execute("SELECT id FROM consultations ORDER BY id DESC")
            count = int(cursor.fetchone()[0])
            # Insert consultation data into the database
            cursor.execute("INSERT INTO consultations (id, user_id, sneaker_id, sneaker_name, consult_notes) "
                           "VALUES (?, ?, ?, ?, ?)",
                           (count+1, consult_data['user_id'], consult_data['sneaker_id'],
                            consult_data['sneaker_name'], consult_data['consult_notes']))
            connection.commit()
            return consult_data
    finally:
        # connection.close()
        print('done')
        
@app.get('/consult/me', tags=['Auth Users'])
async def read_my_consult(
    current_user: Annotated[UserLogin, Depends(get_current_basic_user)]
):
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT id FROM users WHERE username=?", (current_user.username))
            user_id = int(cursor.fetchone()[0])
            cursor.execute("SELECT * FROM consultations WHERE user_id=?", (user_id))
            data = cursor.fetchall()

            consult_list = [{
                'user_id': item[1],
                'username' : current_user.username,
                'sneakers_id': item[2],
                'sneakers_name': item[3],
                'consult_notes': item[4]
            } for item in data]

        if not consult_list:
            raise HTTPException(
                status_code=404, detail=f'Consultations not found'
            )

        return consult_list

    finally:
        print('done')
        # connection.close()
        
@app.post('/sneakers', tags=['Admin'])
async def add_sneakers(
    current_user: Annotated[UserLogin, Depends(get_current_admin)],
    sneakers: Sneakers):
    connection = create_connection()
    try:
        with connection.cursor() as cursor:
            # Check if the sneaker ID already exists
            cursor.execute("SELECT * FROM sneakers WHERE id=?", (sneakers.id,))
            existing_sneaker = cursor.fetchone()
            
            
            if existing_sneaker:
                raise HTTPException(
                    status_code=400, detail=f'Sneaker with ID {sneakers.id} already exists.'
                )

            # Insert the new sneaker into the database
            cursor.execute("INSERT INTO sneakers (id, name, category) VALUES (?, ?, ?)",
                           (sneakers.id, sneakers.name, sneakers.category))
            
            for detail in sneakers.details:
            # Insert the sneaker details into the database
                cursor.execute("SELECT id FROM sneaker_details ORDER BY id DESC")
                count = int(cursor.fetchone()[0])
                cursor.execute("INSERT INTO sneaker_details (id, sneaker_id, sneakersize, stock, price) VALUES (?, ?, ?, ?, ?)",
                            (count+1, sneakers.id, detail.size, detail.stock, detail.price))

            connection.commit()

            return sneakers.dict()
    finally:
        connection.close()   

@app.delete('/sneakers/{sneaker_id}', tags=['Admin'])
async def delete_sneaker(current_user: Annotated[UserLogin, Depends(get_current_admin)]
    ,sneaker_id: int):
    try:
        with connection.cursor() as cursor:
            # Check if the sneaker ID exists
            cursor.execute("SELECT * FROM sneakers WHERE id=?", (sneaker_id,))
            existing_sneaker = cursor.fetchone()

            if not existing_sneaker:
                raise HTTPException(
                    status_code=404, detail=f'Sneaker with ID {sneaker_id} not found.'
                )

            # Delete the sneaker from the database
            cursor.execute("DELETE FROM sneaker_details WHERE sneaker_id=?", (sneaker_id,))
            cursor.execute("DELETE FROM sneakers WHERE id=?", (sneaker_id,))

            connection.commit()

            return "Sneaker deleted"

    finally:
        # connection.close()
        print('done')
        
@app.delete('/user/{user_id}', tags=['Admin'])
async def delete_sneaker(current_user: Annotated[UserLogin, Depends(get_current_admin)]
    ,user_id: int):
    try:
        with connection.cursor() as cursor:
            # Check if the sneaker ID exists
            cursor.execute("SELECT username FROM users WHERE id=?", (user_id,))
            existing_user = cursor.fetchone()

            if not existing_user:
                raise HTTPException(
                    status_code=404, detail=f'User with ID {user_id} not found.'
                )
            
            username = existing_user[0]

            # Delete the sneaker from the database
            cursor.execute("DELETE FROM consultations WHERE user_id=?", (user_id))
            cursor.execute("DELETE FROM users WHERE id=?", (user_id))
            cursor.execute("DELETE FROM users_login WHERE username=?", (username))

            connection.commit()

            return f"User with username {username} deleted"

    finally:
        # connection.close()
        print('done')
        
        
@app.get('/user', tags=['Admin'])
async def read_all_users(current_user: Annotated[UserLogin, Depends(get_current_admin)]):
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT * FROM users")
            users = cursor.fetchall()

            user_list = [{
                'id': item[0],
                'username' : item[5],
                'age': item[1],
                'footsize': item[2],
                'category' : item[3],
                'budget' : item[4]
            } for item in users]

            return user_list
    finally:
        # connection.close()
        print('done')
        
@app.put('/sneakers', tags=['Admin'])
async def update_sneaker(current_user: Annotated[UserLogin, Depends(get_current_admin)],
    sneaker: Sneakers):
    try:
        with connection.cursor() as cursor:
            # Check if the sneaker ID exists
            cursor.execute("SELECT * FROM sneakers WHERE id=?", (sneaker.id,))
            existing_sneaker = cursor.fetchone()

            if not existing_sneaker:
                raise HTTPException(
                    status_code=404, detail=f'Sneaker with ID {sneaker.id} not found.'
                )

            # Update the sneaker in the database
            cursor.execute("UPDATE sneakers SET name=?, category=? WHERE id=?",
                           (sneaker.name, sneaker.category, sneaker.id))

            # Delete existing sneaker details
            cursor.execute("DELETE FROM sneaker_details WHERE sneaker_id=?", (sneaker.id,))

            # Insert the updated sneaker details into the database
            for detail in sneaker.details:
                cursor.execute("SELECT COUNT(id) FROM sneaker_details")
                count = int(cursor.fetchone()[0])
                cursor.execute("INSERT INTO sneaker_details (id, sneaker_id, sneakersize, stock, price) VALUES (?, ?, ?, ?, ?)",
                               (count+1, sneaker.id, detail.size, detail.stock, detail.price))

            connection.commit()

            return "updated"

    finally:
        # connection.close()
        print('done')
        
@app.get('/consult', tags=['Admin'])
async def read_all_consultations(current_user: Annotated[UserLogin, Depends(get_current_admin)]):
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT * FROM consultations")
            data = cursor.fetchall()

            consultations = [{
                'consultation_id': item[0],
                'user_id': item[1],
                'sneakers_id': item[2],
                'sneakers_name': item[3],
                'consult_notes': item[4]
            } for item in data]

            return consultations

    finally:
        # connection.close()
        print('done')