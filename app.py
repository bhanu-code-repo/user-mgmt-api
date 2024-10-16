# app.py
from flask import Flask
from flasgger import Swagger
from api.user_routes import user_bp

app = Flask(__name__)

# Initialize Swagger
swagger = Swagger(app)

# Register the user blueprint
app.register_blueprint(user_bp)

if __name__ == "__main__":
    app.run(debug=True)
