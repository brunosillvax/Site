from flask import (
    Flask, render_template, request, jsonify,
    redirect, url_for, session, flash
)
from flask_cors import CORS
from instagrapi import Client
from instagrapi.exceptions import (
    UserNotFound, PrivateAccount, BadPassword, ChallengeRequired
)
from dotenv import load_dotenv
import os

load_dotenv()

app = Flask(__name__)
CORS(app, origins=["https://brunosillvax.github.io"])

app.secret_key = os.getenv("SECRET_KEY") or "chave_secreta_qualquer"

# resto do seu código segue igual

cl = Client()
session_path = "sessions/insta_session.json"
username_login = os.getenv("INSTAGRAM_USERNAME")
password_login = os.getenv("INSTAGRAM_PASSWORD")

os.makedirs("sessions", exist_ok=True)

try:
    if os.path.exists(session_path):
        cl.load_settings(session_path)
        cl.login(username_login, password_login)
        cl.dump_settings(session_path)
    else:
        cl.login(username_login, password_login)
        cl.dump_settings(session_path)
except BadPassword:
    print("⚠️  Senha incorreta. Verifique suas credenciais no .env.")
except ChallengeRequired:
    print("⚠️  Instagram solicitou verificação adicional. Autorize o acesso na conta.")
except Exception as e:
    print(f"⚠️  Erro inesperado ao logar: {e}")

cl.public_requests = False

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        usuario = request.form.get("usuario")
        senha = request.form.get("senha")

        if usuario == "admin" and senha == "123":
            session["usuario_logado"] = usuario
            return redirect(url_for("home"))
        else:
            flash("Usuário ou senha inválidos")
            return redirect(url_for("login"))
    return render_template("login.html")

@app.route("/")
def home():
    if "usuario_logado" not in session:
        return redirect(url_for("login"))
    return render_template("index.html")

@app.route("/logout")
def logout():
    session.pop("usuario_logado", None)
    return redirect(url_for("login"))

@app.route("/api/buscar", methods=["POST"])
def buscar():
    if "usuario_logado" not in session:
        return jsonify({"error": "Usuário não autenticado"}), 401

    data = request.json
    username = data.get("username", "").strip()

    if not username:
        return jsonify({"error": "Username não informado"}), 400

    try:
        user = cl.user_info_by_username(username)
        dados = {
            "username": username,
            "nome": user.full_name,
            "foto": str(user.profile_pic_url),
            "seguidores": user.follower_count,
            "seguindo": user.following_count,
            "bio": user.biography,
        }
        return jsonify(dados)

    except UserNotFound:
        return jsonify({"error": "Usuário não encontrado"}), 404
    except PrivateAccount:
        return jsonify({"error": "Conta privada"}), 403
    except ChallengeRequired:
        return jsonify({"error": "Instagram pediu verificação adicional (challenge)"}), 403
    except Exception as e:
        return jsonify({"error": "Erro inesperado: " + str(e)}), 500

@app.route("/api/comentarios", methods=["POST"])
def comentarios():
    if "usuario_logado" not in session:
        return jsonify({"error": "Usuário não autenticado"}), 401

    data = request.json
    username = data.get("username", "").strip()

    if not username:
        return jsonify({"error": "Username não informado"}), 400

    try:
        user = cl.user_info_by_username(username)
        medias = cl.user_medias(user.pk, 5)  # últimos 5 posts

        lista_comentarios = []

        for media in medias:
            comments = cl.media_comments(media.pk)
            for c in comments:
                lista_comentarios.append({
                    "post_url": f"https://www.instagram.com/p/{media.code}/",
                    "commenter": c.user.username,
                    "text": c.text,
                    "created_at": c.created_at.strftime("%Y-%m-%d %H:%M:%S"),
                })

        return jsonify({"comentarios": lista_comentarios})

    except UserNotFound:
        return jsonify({"error": "Usuário não encontrado"}), 404
    except PrivateAccount:
        return jsonify({"error": "Conta privada"}), 403
    except Exception as e:
        return jsonify({"error": "Erro inesperado: " + str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True)
