from app import app, db  # Ensure you import your app and db objects from your main app file

with app.app_context():
    db.create_all()
    print("Database tables created!")