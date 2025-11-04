from flask import Flask

app = Flask(__name__)

# Import routes at the end — inside a function to avoid circular import
def register_routes():
    from app import routes  # import only when needed
    return app

register_routes()