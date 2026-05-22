#!/usr/bin/env python
"""
Create a test user account for MediVault
Run this script to add a test user to your database
"""

import sys
sys.path.insert(0, '.')

from app import app
from models import db, User
from werkzeug.security import generate_password_hash

def create_test_user():
    with app.app_context():
        # Check if test user already exists
        existing_user = User.query.filter_by(username='testaccount').first()
        
        if existing_user:
            print("\n✓ Test user already exists!")
            print(f"  Username: testaccount")
            print(f"  Role: {existing_user.role}")
        else:
            # Create new test user
            test_user = User(
                username='testaccount',
                password_hash=generate_password_hash('TestPassword123!'),
                role='patient'
            )
            db.session.add(test_user)
            db.session.commit()
            print("\n✓ Test user created successfully!")
            print(f"  Username: testaccount")
            print(f"  Password: TestPassword123!")
            print(f"  Role: patient")
        
        print("\n" + "="*70)
        print("LOGIN CREDENTIALS:")
        print("="*70)
        print("  URL:      http://localhost:5000/login")
        print("  Username: testaccount")
        print("  Password: TestPassword123!")
        print("="*70 + "\n")

if __name__ == '__main__':
    create_test_user()
