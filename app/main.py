from flask import Flask
from mongoengine import connect
from app_routes.auth_routes import auth_bp
from app_routes.user_routes import user_bp


app = Flask(__name__)
app.secret_key = 'clave secreta'
connect(host='mongo', port=27017)#,db='proycd-oto2024'

app.register_blueprint(auth_bp)
app.register_blueprint(user_bp)



if __name__ == '__main__':
    app.run(host="0.0.0.0", debug=True, port=5000)