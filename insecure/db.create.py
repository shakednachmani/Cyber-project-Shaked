from app import app, db
from sqlalchemy import text

with app.app_context():
    with open('schema.sql', 'r') as file:
        schema_sql = file.read()

    sql_statements = schema_sql.split(';')
    
    for statement in sql_statements:
        if statement.strip(): 
            db.session.execute(text(statement.strip()))
    
    db.session.commit()  
    print("Database tables created from SQL schema!")
