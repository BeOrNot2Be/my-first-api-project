from flask import Flask, request, jsonify, render_template, url_for, g
import sys
import re
import asyncio
import os.path
import datetime
import multiprocessing
from flask_httpauth import HTTPBasicAuth
db_dir = (
    os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    + '/db/')
sys.path.append(db_dir)
from model import (
    make_server, update_server,
    get_servers, get_server,
    delate_server, session,
    ping_request, Server,
    User)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'thisissecret'
auth = HTTPBasicAuth()


@auth.verify_password
def verify_password(username_or_token, password):
    # first try to authenticate by token
    user = User.verify_auth_token(token=username_or_token, app=app)
    if not user:
        # try to authenticate with username/password
        user = session.query(User).filter_by(username=username_or_token)
        user = user.first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True


@app.route('/api/users/<int:id>')
def get_user(id):
    user = session.query(User).filter_by(id=id).first()
    if not user:
        status = "THE_USERNAME_UNEXPECTED"
        return jsonify({"status": status})
    return jsonify({'username': user.username})


@app.route('/api/users', methods=['POST'])
def new_user():
    username = request.json.get('username')
    password = request.json.get('password')
    if username is None or password is None:
        status = "ENTER_USERNAME_AND_PASSWORD"
        return jsonify({"status": status})
    if session.query(User).filter_by(username=username).first() is not None:
        status = "THE_USERNAME_ENGAGED"
        return jsonify({"status": status})
    user = User(username=username)
    user.hash_password(password)
    session.add(user)
    session.commit()
    return (
        jsonify({'username': user.username}), 201,
        {'Location': url_for('get_user', id=user.id, _external=True)})


@app.route('/api/resource')
@auth.login_required
def get_resource():
    return jsonify({'data': f'Hello, {g.user.username}!'})


@app.route('/api/token')
@auth.login_required
def get_auth_token():
    token = g.user.generate_auth_token(app=app)
    return jsonify({'token': token.decode('ascii')})


@app.route('/', methods=['GET', 'POST', 'PUT', 'DELETE'])
def start():

    if request.method == 'POST':
        try:
            date = request.get_json(silent=True)['server']
            name = str(date['name'])
            IP = str(date['IP'])
            if make_server(name=name, IP=IP):
                status = 'CREATED'
            else:
                status = "NAME_DID_NOT_FOUND"
            return jsonify({"status": status})
        except Exception:
            status = "WRONG_REQUESTE"
            return jsonify({"status": status})

    if request.method == 'PUT':
        try:
            date = request.get_json(silent=True)['server']
            name = str(date['name'])
            IP = str(date['IP'])
            if update_server(name=name, IP=IP):
                status = 'UPDATE'
            else:
                status = "NAME_DID_NOT_FOUND"
            return jsonify({"status": status})
        except Exception:
            status = "WRONG_REQUESTE"
            return jsonify({"status": status})

    if request.method == 'GET':
        try:
            return render_template('get_all.html', servers=get_servers())

        except Exception as e:
            return jsonify({"status": "ERRORE"})

    if request.method == 'DELETE':
        try:
            date = request.get_json(silent=True)['server']
            name = str(date['name'])
            if delate_server(name=name):
                status = 'DELETE'
            else:
                status = "NAME_DID_NOT_FOUND"
        except Exception:
            status = "NAME_DID_NOT_FOUND"
        finally:
            return jsonify({"status": status})


@auth.login_required
@app.route('/<server_name>', methods=['GET'])
def get(server_name):
    try:
        server_info = get_server(name=str(server_name))
        if not server_info:
            status = "NOT_PINGED_YET"
            return jsonify({"status": status})
        answer = server_info[-5:]
        time = []
        ms = []
        answer2 = {}
        for i in answer:
            answer2.update(i)
        time = list(answer2.keys())
        ms = list(answer2.values())
        server_info.reverse()
        return render_template(
            'get_precise_server.html', server=server_name,
            time=time, ms=ms,
            pings=server_info)

    except Exception as a:
        print(a)
        status = "NAME_DID_NOT_FOUND"
        return jsonify({"status": status})


async def ping(loop, server):
    while True:
        p = await asyncio.create_subprocess_exec(
            'ping', server.IP,
            stdout=asyncio.subprocess.PIPE, loop=loop)

        async for line in p.stdout:
            parsed = re.search(r"Average = \d+ms", line.decode())
            if parsed:
                parsed1 = re.search(r"\d+", str(parsed.group(0)))
                print(server.name, "==>", parsed1.group(0))
                new_ping_request = ping_request(
                        server_id=server.id,
                        response_time=parsed1.group(0),
                        datetime=datetime.datetime.utcnow())
                session.add(new_ping_request)
                session.commit()

        await asyncio.sleep(5)


def pinging():
    while True:
        loop = asyncio.ProactorEventLoop()
        asyncio.set_event_loop(loop)
        tasks = []
        servers = session.query(Server).all()
        if servers:
            for server in servers:
                tasks.append(ping(loop, server))
            loop.run_until_complete(asyncio.wait(tasks))
            loop.run_until_complete()
            loop.close()


if __name__ == '__main__':
    t1 = multiprocessing.Process(target=pinging)
    t1.start()
    t2 = multiprocessing.Process(target=app.run())
    t2.start()
