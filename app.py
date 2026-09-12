from flask import Flask, render_template

from config import Config
from extensions import db, csrf, limiter, mail, login_manager


def create_app():
    """Create and configure the Flask application."""

    app = Flask(__name__)
    app.config.from_object(Config)

    # Initialize extensions
    db.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)
    mail.init_app(app)
    login_manager.init_app(app)

    # Import models so SQLAlchemy knows about them.
    from models import User, Scan  # noqa: F401

    from auth import auth_bp
    from scan_routes import scan_bp
    app.register_blueprint(auth_bp)
    app.register_blueprint(scan_bp)

    # Create database tables.
    with app.app_context():
        db.create_all()

    @app.route("/")
    def home():
        return render_template("index.html")

    @app.errorhandler(404)
    def not_found(_e):
        return render_template("errors/404.html"), 404

    @app.errorhandler(500)
    def server_error(_e):
        return render_template("errors/500.html"), 500

    return app


app = create_app()


if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 7860))
    app.run(host="0.0.0.0", port=port, debug=False)
