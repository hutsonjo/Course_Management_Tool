import io

from flask import Flask, request, jsonify, url_for, send_file
from google.cloud import datastore, storage
from google.cloud.exceptions import NotFound

import requests
import json

from six.moves.urllib.request import urlopen
from jose import jwt
from authlib.integrations.flask_client import OAuth

app = Flask(__name__)
app.secret_key = 'SECRET_KEY'

client = datastore.Client()
storage_client = storage.Client()
bucket = storage_client.get_bucket('cs493-hutsonjo')

USERS = 'users'
AVATAR = 'avatar'
COURSES = 'courses'
ERROR_400 = {'Error': "The request body is invalid"}
ERROR_401 = {'Error': 'Unauthorized'}
ERROR_403 = {'Error': "You don't have permission on this resource"}
ERROR_404 = {'Error': "Not Found"}
ERROR_409 = {"Error": "Enrollment data is invalid"}

CLIENT_ID = 'yjITYspDOY6YE65RV3qDWrbn9YwX63wY'
CLIENT_SECRET = 'wSFwfgfC6zQ17Dh2bD7ij50I9fg5MpvXc_NJ2goU44OOHhVECZFL9cuzGKGBAIJU'
DOMAIN = 'dev-xnlrmo0sb42s61mb.us.auth0.com'
ALGORITHMS = ["RS256"]

oauth = OAuth(app)

auth0 = oauth.register(
    'auth0',
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    api_base_url="https://" + DOMAIN,
    access_token_url="https://" + DOMAIN + "/oauth/token",
    authorize_url="https://" + DOMAIN + "/authorize",
    client_kwargs={
        'scope': 'openid profile email',
    },
)


class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response


# Verify the JWT in the request's Authorization header
def verify_jwt(request):
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        token = auth_header[1]
    else:
        raise AuthError(ERROR_401, 401)

    jsonurl = urlopen("https://" + DOMAIN + "/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        raise AuthError(ERROR_401, 401)
    if unverified_header["alg"] == "HS256":
        raise AuthError(ERROR_401, 401)
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=CLIENT_ID,
                issuer="https://" + DOMAIN + "/"
            )
        except jwt.ExpiredSignatureError:
            raise AuthError(ERROR_401, 401)
        except jwt.JWTClaimsError:
            raise AuthError(ERROR_401, 401)
        except Exception:
            raise AuthError(ERROR_401, 401)

        return payload
    else:
        raise AuthError(ERROR_401, 401)


def verify_admin(payload):
    # Verify valid JWT and admin log in
    admin_id = payload['sub']
    query = client.query(kind=USERS)
    query.add_filter('sub', '=', admin_id)
    query.add_filter('role', '=', 'admin')
    results = list(query.fetch())
    if not results:
        raise AuthError(ERROR_403, 403)


def verify_user(req, user_id):
    payload = verify_jwt(req)
    user_key = client.key(USERS, user_id)
    user = client.get(key=user_key)
    if payload['sub'] != user['sub']:
        raise AuthError(ERROR_403, 403)
    return user


def course_validation(course):
    required_keys = ['subject', 'number', 'title', 'term', 'instructor_id']
    if not all(key in course for key in required_keys):
        raise AuthError(ERROR_400, 400)


def instructor_validation(course):
    if course['instructor_id']:
        instructor_id = course['instructor_id']
        instructor_key = client.key(USERS, instructor_id)
        instructor = client.get(key=instructor_key)
        if not instructor or instructor['role'] != 'instructor':
            raise AuthError(ERROR_400, 400)
        return instructor


def retrieve_admin():
    query = client.query(kind=USERS)
    query.add_filter('role', '=', 'admin')
    admin_query = list(query.fetch(limit=1))
    admin = admin_query[0] if admin_query else None
    return admin


@app.route('/')
def index():
    return "Please navigate to /businesses to use this API" \
 \


# Decode the JWT supplied in the Authorization header
@app.route('/decode', methods=['GET'])
def decode_jwt():
    payload = verify_jwt(request)
    return payload


# Generate a JWT from the Auth0 domain and return it
# Request: JSON body with 2 properties with "username" and "password"
#       of a user registered with this Auth0 domain
# Response: JSON with the JWT as the value of the property id_token
@app.route('/' + USERS + '/login', methods=['POST'])
def login_user():
    content = request.get_json()
    if not content['username'] and not content['password']:
        return ERROR_400, 400
    username = content["username"]
    password = content["password"]
    body = {'grant_type': 'password', 'username': username,
            'password': password,
            'client_id': CLIENT_ID,
            'client_secret': CLIENT_SECRET
            }
    headers = {'content-type': 'application/json'}
    url = 'https://' + DOMAIN + '/oauth/token'
    r = requests.post(url, json=body, headers=headers)
    data = r.json()
    id_token = data.get('id_token', None)
    return {'token': id_token}, 200, {'Content-Type': 'application/json'}


@app.route('/' + USERS, methods=['GET'])
def get_users():
    # Verify valid JWT and admin log in
    payload = verify_jwt(request)
    verify_admin(payload)

    # Fetch list of users, return list with only id, role, and sub properties
    query = client.query(kind=USERS)
    results = list(query.fetch())
    return_list = []
    for entity in results:
        return_list.append(
            {'id': entity.id, 'role': entity.role, 'sub': entity.sub}
        )
    return return_list


@app.route('/' + USERS + '/<int:user_id>', methods=['GET'])
def get_user(user_id):
    # Verify valid JWT and fetch target user & admin entities
    payload = verify_jwt(request)
    user_key = client.key(USERS, user_id)
    user = client.get(key=user_key)
    admin = retrieve_admin()

    # Ensure requesting user is either admin or target user, return user if so
    if payload['sub'] != admin['sub'] and payload['sub'] != user['sub']:
        return ERROR_403, 403
    return user


@app.route('/' + USERS + '/<int:user_id>/' + AVATAR, methods=['POST'])
def create_update_user_avatar(user_id):
    # 400 series status code routes
    if 'file' not in request.files:
        return ERROR_400, 400
    user = verify_user(request, user_id)

    # Obtain the file, assign the user id as the file name, and upload it to storage
    file_obj = request.files['file']
    blob = bucket.blob(str(user_id))
    file_obj.seek(0)
    blob.upload_from_file(file_obj)

    # Create an avatar url property and add it to user entity
    avatar_url = url_for('get_user_avatar', user_id=user_id, _external=True)
    user.update({'avatar_url': avatar_url})
    client.put(user)
    return {'avatar_url': avatar_url}


@app.route('/' + USERS + '/<int:user_id>/' + AVATAR, methods=['GET'])
def get_user_avatar(user_id):
    # Verify valid JWT and matching request/target user
    verify_user(request, user_id)

    # Search for file, returning 404 if not found, returning otherwise
    blob = bucket.blob(str(user_id))
    file_obj = io.BytesIO()
    try:
        blob.download_to_file(file_obj)
    except NotFound:
        return ERROR_404, 404
    file_obj.seek(0)
    return send_file(file_obj, mimetype='image/x-png', download_name=str(user_id))


@app.route('/' + USERS + '/<int:user_id>/' + AVATAR, methods=['DELETE'])
def delete_user_avatar(user_id):
    # Verify valid JWT and matching request/target user
    user = verify_user(request, user_id)

    # Delete file and remove avatar_url property from corresponding user
    blob = bucket.blob(str(user_id))
    file_obj = io.BytesIO()
    try:
        blob.download_to_file(file_obj)
    except NotFound:
        return ERROR_404, 404
    blob.delete()
    user.pop('avatar_url', None)
    client.put(user)
    return '', 204


@app.route('/' + COURSES, methods=['POST'])
def create_course():
    # Verify admin status via JWT and validate request body
    payload = verify_jwt(request)
    verify_admin(payload)
    content = request.get_json()
    course_validation(content)

    # Create new course entity
    new_key = client.key(COURSES)
    new_course = datastore.Entity(key=new_key)
    new_course.update({
        'subject': content['subject'],
        'number': content['number'],
        'title': content['title'],
        'term': content['term'],
        'instructor_id': content['instructor_id']
    })
    client.put(new_course)
    new_course['id'] = new_course.key.id


    return new_course, 201


@app.route('/' + COURSES, methods=['GET'])
def get_courses():
    # Pull limit and offset parameters from request
    limit = request.args.get('limit', 3, type=int)
    offset = request.args.get('offset', 0, type=int)

    # Query for all courses by subject with limit and offset, return
    query = client.query(kind=COURSES)
    query.order = ['subject']
    results = list(query.fetch(limit=limit, offset=offset))
    return results


@app.route('/' + COURSES + '/<:course_id>', methods=['GET'])
def get_course(course_id):
    # Query to find course with course id param
    course_key = client.key(COURSES, course_id)
    course = client.get(key=course_key)

    # Verify course exists, reply accordingly
    if not course:
        return ERROR_404, 404
    course['id'] = course_id
    return course


@app.route('/' + COURSES + '/<:course_id>', methods=['PUT'])
def put_course(course_id):
    # Verify JWT, admin status, and valid
    payload = verify_jwt(request)
    verify_admin(payload)
    content = request.get_json()
    instructor_validation(content)

    # add comment
    course_key = client.key(COURSES, course_id)
    course = client.get(key=course_key)
    if not course:
        return ERROR_404, 404
    course.update({
        'subject': content.get('subject', course.get('subject')),
        'number': content.get('number', course.get('number')),
        'title': content.get('title', course.get('title')),
        'term': content.get('term', course.get('term')),
        'instructor_id': content.get('instructor_id', course.get('instructor_id'))
    })
    client.put(course)
    course['id'] = course_id
    return course


@app.route('/' + COURSES + '/<:course_id>', methods=['DELETE'])
def delete_course(course_id):
    # Verify JWT and that course exists
    payload = verify_jwt(request)
    verify_admin(payload)
    course_key = client.key(COURSES, course_id)
    course = client.get(key=course_key)
    if not course:
        return ERROR_403, 403

    # delete course and send 204
    client.delete(course_key)
    return '', 204


@app.route('/' + COURSES + '/<:course_id>/students', methods=['PATCH'])
def patch_course(course_id):
    # Verify validity of JWT and that the course exists
    payload = verify_jwt(request)
    course_key = client.key(COURSES, course_id)
    course = client.get(key=course_key)
    if not course:
        return ERROR_403, 403

    # Validate that the JWT belongs to an admin or the course instructor
    course.get_json()
    instructor = instructor_validation(course)
    instructor.get_json()
    admin = retrieve_admin()
    if admin['sub'] != payload['sub'] and instructor['sub'] != payload['sub']:
        return ERROR_403, 403

    # Validate request content
    content = request.get_json()
    if not content['add'] and not content['remove']:
        return ERROR_409, 409

    # Form course url and add it to any student on the list if not already enrolled & 409 for false user_ids
    course_url = f'{request.host_url}/courses/{course_id}'
    for student_id in content['add']:
        student_key = client.key(USERS, student_id)
        student = client.get(key=student_key)
        if not student:
            return ERROR_409, 409
        if course_url not in student['courses']:
            student['courses'].append(course_url)

    # Remove course_url from any student currently enrolled & 409 for false user_ids
    for student_id in content['remove']:
        student_key = client.key(USERS, student_id)
        student = client.get(key=student_key)
        if not student:
            return ERROR_409, 409
        if course_url in student['courses']:
            student['courses'].remove(course_url)


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)