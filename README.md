# Flask JWT with SQLAlchemy

Playing around with `JSON Web Token Authentication` and `Flask-SQLAlchemy`.

---

## Project setup for Development

1. Clone the repository

2. Change directory to `api/` and create two `environment variable files` by the name `.flaskenv` and `.env`.

    1. `.flaskenv` will contain the flask CLI variables.

    2. `.env` will contain the flask config variables.

3. Create a `Database.db` file (you can use any file name or SQL Database, just make the necessary changes in the config)

4. Open up a python shell and type the following:

    ```
    >> from app import db
    >> db.create_all()
    ```

    This will create all the Tables from the ORMs

5. Lastly run the command `flask run` and now your api should be serving at `http://localhost:8080`.

---

## Libraries used

1. Flask

2. Flask-SQLAlchemy

3. PyJWT (for authentication)

---