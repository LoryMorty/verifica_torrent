from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
from pymongo import MongoClient
import os
import bcrypt
import jwt
from datetime import datetime, timedelta
from functools import wraps

# =========================
# CONFIGURAZIONE
# =========================

MONGODB_URI = os.getenv(
    "MONGODB_URI",
    "mongodb+srv://Mortillaro_Lorenzo:Lory_230807@cluster0.zgxlfeh.mongodb.net/"
)

JWT_SECRET = os.getenv("JWT_SECRET", "Lory_Torrent_App_Secret_12345")
JWT_ALGORITHM = "HS256"

client = MongoClient(MONGODB_URI)
db = client["Verifica_Torrent"]        # <--- nome DB come su Atlas

users_col = db["utenti"]               # <--- nome collection utenti
torrents_col = db["torrents"]
comments_col = db["commenti"]

app = Flask(__name__)
CORS(app)


# =========================
# FUNZIONI DI SUPPORTO
# =========================

def get_next_id(collection):
    """Usa il campo 'id' numerico, non _id."""
    doc = collection.find_one(sort=[("id", -1)])
    if doc and "id" in doc:
        return int(doc["id"]) + 1
    return 1


def create_token(user_doc):
    payload = {
        "userId": int(user_doc["id"]),
        "role": user_doc.get("role", "user"),
        "isBanned": user_doc.get("isBanned", False),
        "exp": datetime.utcnow() + timedelta(hours=2)
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    # PyJWT può restituire bytes in alcune versioni
    if isinstance(token, bytes):
        token = token.decode("utf-8")
    return token


def decode_token(token):
    return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])


def auth_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"message": "Token mancante o non valido"}), 401
        token = auth_header.split(" ")[1]
        try:
            payload = decode_token(token)
        except Exception:
            return jsonify({"message": "Token non valido"}), 401

        request.user = {
            "id": int(payload["userId"]),
            "role": payload["role"],
            "isBanned": payload["isBanned"]
        }
        return f(*args, **kwargs)

    return wrapper


def require_role(*roles):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            u = getattr(request, "user", None)
            if not u:
                return jsonify({"message": "Non autenticato"}), 401
            if u["role"] not in roles:
                return jsonify({"message": "Non autorizzato"}), 403
            return f(*args, **kwargs)
        return wrapper
    return decorator


def user_to_public(u):
    return {
        "id": int(u["id"]),
        "username": u["username"],
        "email": u["email"],
        "role": u.get("role", "user"),
        "isBanned": u.get("isBanned", False)
    }


def torrent_to_public(t):
    return {
        "id": int(t["id"]),
        "title": t["title"],
        "description": t["description"],
        "size": t["size"],
        "categories": t.get("categories", []),
        "images": t.get("images", []),
        "torrentFileUrl": t["torrentFileUrl"],
        "uploadedBy": t.get("uploadedBy"),
        "downloadCount": t.get("downloadCount", 0),
        "averageRating": t.get("averageRating", 0),
        "createdAt": t.get("createdAt"),
        "updatedAt": t.get("updatedAt")
    }


def comment_to_public(c):
    return {
        "id": int(c["id"]),
        "torrentId": c["torrentId"],
        "userId": c["userId"],
        "rating": c["rating"],
        "text": c["text"],
        "createdAt": c.get("createdAt"),
        "updatedAt": c.get("updatedAt")
    }


def update_torrent_average(torrent_id):
    comments = list(comments_col.find({"torrentId": torrent_id}))
    if not comments:
        torrents_col.update_one({"id": torrent_id}, {"$set": {"averageRating": 0}})
        return
    avg = sum(c["rating"] for c in comments) / len(comments)
    torrents_col.update_one(
        {"id": torrent_id},
        {"$set": {"averageRating": round(avg, 2)}}
    )


# =========================
# SERVE LA SPA
# =========================

@app.route("/")
def index():
    return send_from_directory(".", "index.html")


# =========================
# API DI TEST
# =========================

@app.route("/api/health")
def health():
    return jsonify({
        "status": "ok",
        "message": "Backend Flask torrent funzionante",
        "timestamp": datetime.utcnow().isoformat()
    })


# =========================
# AUTH
# =========================

@app.route("/api/auth/register", methods=["POST"])
def register():
    data = request.get_json() or {}
    username = data.get("username")
    email = data.get("email")
    password = data.get("password")

    if not username or not email or not password:
        return jsonify({"message": "username, email e password sono obbligatori"}), 400

    existing = users_col.find_one({"$or": [{"username": username}, {"email": email}]})
    if existing:
        return jsonify({"message": "Username o email già usati"}), 400

    password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    new_id = get_next_id(users_col)
    now = datetime.utcnow().isoformat()

    user_doc = {
        "id": new_id,
        "username": username,
        "email": email,
        "passwordHash": password_hash,
        "role": "user",
        "isBanned": False,
        "createdAt": now,
        "updatedAt": now
    }

    users_col.insert_one(user_doc)

    return jsonify({
        "message": "Registrazione completata",
        "user": user_to_public(user_doc)
    }), 201


@app.route("/api/auth/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"message": "email e password sono obbligatorie"}), 400

    user = users_col.find_one({"email": email})
    if not user:
        return jsonify({"message": "Credenziali non valide"}), 401

    if not bcrypt.checkpw(password.encode("utf-8"), user["passwordHash"].encode("utf-8")):
        return jsonify({"message": "Credenziali non valide"}), 401

    if user.get("isBanned"):
        return jsonify({"message": "Utente bannato"}), 403

    token = create_token(user)

    return jsonify({
        "message": "Login effettuato",
        "token": token,
        "user": user_to_public(user)
    })


@app.route("/api/auth/me", methods=["GET"])
@auth_required
def me():
    u = users_col.find_one({"id": request.user["id"]})
    if not u:
        return jsonify({"message": "Utente non trovato"}), 404
    return jsonify({"user": user_to_public(u)})


# =========================
# API TORRENTS
# =========================

@app.route("/api/torrents", methods=["POST"])
@auth_required
def create_torrent():
    if request.user["isBanned"]:
        return jsonify({"message": "Utente bannato, non può caricare torrent"}), 403

    data = request.get_json() or {}
    title = data.get("title")
    description = data.get("description")
    size = data.get("size")
    categories = data.get("categories")
    images = data.get("images") or []
    torrentFileUrl = data.get("torrentFileUrl")

    if not title or not description or size is None or not categories or not torrentFileUrl:
        return jsonify({"message": "title, description, size, categories, torrentFileUrl sono obbligatori"}), 400

    new_id = get_next_id(torrents_col)
    now = datetime.utcnow().isoformat()

    torrent_doc = {
        "id": new_id,
        "title": title,
        "description": description,
        "size": int(size),
        "categories": categories,
        "images": images,
        "torrentFileUrl": torrentFileUrl,
        "uploadedBy": request.user["id"],
        "downloadCount": 0,
        "averageRating": 0,
        "createdAt": now,
        "updatedAt": now
    }

    torrents_col.insert_one(torrent_doc)
    return jsonify(torrent_to_public(torrent_doc)), 201


@app.route("/api/torrents", methods=["GET"])
def list_torrents():
    q_title = request.args.get("qTitle")
    q_desc = request.args.get("qDescription")
    categories_param = request.args.getlist("categories")
    date_from = request.args.get("dateFrom")
    date_to = request.args.get("dateTo")
    sort_by = request.args.get("sortBy")   # "date" | "size"
    order = request.args.get("order")      # "asc" | "desc"

    filters = {}

    if q_title:
        filters["title"] = {"$regex": q_title, "$options": "i"}
    if q_desc:
        filters["description"] = {"$regex": q_desc, "$options": "i"}

    if categories_param:
        cats = []
        for c in categories_param:
            cats.extend([x.strip() for x in c.split(",") if x.strip()])
        filters["categories"] = {"$in": cats}

    if date_from or date_to:
        filters["createdAt"] = {}
        if date_from:
            filters["createdAt"]["$gte"] = date_from
        if date_to:
            filters["createdAt"]["$lte"] = date_to

    sort_field = "createdAt"
    if sort_by == "size":
        sort_field = "size"
    sort_dir = -1
    if order == "asc":
        sort_dir = 1

    cursor = torrents_col.find(filters).sort(sort_field, sort_dir)
    torrents = [torrent_to_public(t) for t in cursor]
    return jsonify(torrents)


@app.route("/api/torrents/<int:torrent_id>", methods=["GET"])
def get_torrent(torrent_id):
    t = torrents_col.find_one({"id": torrent_id})
    if not t:
        return jsonify({"message": "Torrent non trovato"}), 404
    return jsonify(torrent_to_public(t))


@app.route("/api/torrents/<int:torrent_id>/download", methods=["GET"])
@auth_required
def download_torrent(torrent_id):
    if request.user["isBanned"]:
        return jsonify({"message": "Utente bannato, non può scaricare"}), 403

    t = torrents_col.find_one({"id": torrent_id})
    if not t:
        return jsonify({"message": "Torrent non trovato"}), 404

    torrents_col.update_one({"id": torrent_id}, {"$inc": {"downloadCount": 1}})

    return jsonify({
        "message": "Download conteggiato",
        "torrentFileUrl": t["torrentFileUrl"]
    })


@app.route("/api/torrents/<int:torrent_id>", methods=["DELETE"])
@auth_required
@require_role("moderator", "admin")
def delete_torrent(torrent_id):
    res = torrents_col.delete_one({"id": torrent_id})
    if res.deleted_count == 0:
        return jsonify({"message": "Torrent non trovato"}), 404
    comments_col.delete_many({"torrentId": torrent_id})
    return jsonify({"message": "Torrent cancellato"})


# =========================
# API COMMENTI
# =========================

@app.route("/api/torrents/<int:torrent_id>/comments", methods=["GET"])
def list_comments(torrent_id):
    docs = comments_col.find({"torrentId": torrent_id}).sort("createdAt", -1)
    return jsonify([comment_to_public(c) for c in docs])


@app.route("/api/torrents/<int:torrent_id>/comments", methods=["POST"])
@auth_required
def create_comment(torrent_id):
    if request.user["isBanned"]:
        return jsonify({"message": "Utente bannato, non può commentare"}), 403

    data = request.get_json() or {}
    rating = data.get("rating")
    text = data.get("text")

    if rating is None or text is None:
        return jsonify({"message": "rating e text sono obbligatori"}), 400

    rating = int(rating)
    if not (1 <= rating <= 5):
        return jsonify({"message": "rating deve essere tra 1 e 5"}), 400

    existing = comments_col.find_one({
        "torrentId": torrent_id,
        "userId": request.user["id"]
    })
    if existing:
        return jsonify({"message": "Hai già commentato questo torrent"}), 400

    new_id = get_next_id(comments_col)
    now = datetime.utcnow().isoformat()

    comment_doc = {
        "id": new_id,
        "torrentId": torrent_id,
        "userId": request.user["id"],
        "rating": rating,
        "text": text,
        "createdAt": now,
        "updatedAt": now
    }
    comments_col.insert_one(comment_doc)
    update_torrent_average(torrent_id)
    return jsonify(comment_to_public(comment_doc)), 201


@app.route("/api/comments/<int:comment_id>", methods=["DELETE"])
@auth_required
def delete_comment(comment_id):
    comment = comments_col.find_one({"id": comment_id})
    if not comment:
        return jsonify({"message": "Commento non trovato"}), 404

    if comment["userId"] != request.user["id"] and request.user["role"] not in ("moderator", "admin"):
        return jsonify({"message": "Non autorizzato"}), 403

    comments_col.delete_one({"id": comment_id})
    update_torrent_average(comment["torrentId"])
    return jsonify({"message": "Commento cancellato"})


# =========================
# API STATISTICHE (ADMIN)
# =========================

@app.route("/api/stats/top-torrents", methods=["GET"])
@auth_required
@require_role("admin")
def stats_top_torrents():
    by = request.args.get("by", "downloads")  # downloads | rating
    limit = int(request.args.get("limit", 10))
    sort_field = "downloadCount" if by == "downloads" else "averageRating"
    torrents = torrents_col.find().sort(sort_field, -1).limit(limit)
    return jsonify([torrent_to_public(t) for t in torrents])


@app.route("/api/stats/torrents-per-category", methods=["GET"])
@auth_required
@require_role("admin")
def stats_torrents_per_category():
    pipeline = [
        {"$unwind": "$categories"},
        {"$group": {"_id": "$categories", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}}
    ]
    result = list(torrents_col.aggregate(pipeline))
    return jsonify([{"category": r["_id"], "count": r["count"]} for r in result])


# =========================
# AVVIO
# =========================

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
