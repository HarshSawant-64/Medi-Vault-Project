#!/usr/bin/env python
"""
Simple startup script for MediVault Flask app
This ensures all dependencies from the virtual environment are used
"""

if __name__ == '__main__':
    from app import app
    print("\n" + "="*70)
    print("MEDIVAULT - Starting Flask Server")
    print("="*70)
    print("\nServer starting at: http://localhost:5000")
    print("\nAccess the app at:")
    print("  - Login: http://localhost:5000/login")
    print("  - Home: http://localhost:5000")
    print("\nTo stop the server, press Ctrl+C")
    print("="*70 + "\n")
    
    # Start the server with debug mode enabled for development
    app.run(debug=True, host='127.0.0.1', port=5000)
