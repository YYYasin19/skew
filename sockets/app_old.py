from flask import Flask, jsonify, abort, request
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_socketio import SocketIO, join_room, emit
from flask_mongoengine import MongoEngine
import mongoengine as me

app = Flask(__name__)
app.config.from_pyfile('config.py')
app.config['MONGODB_SETTINGS'] = {
    'db':'',
    'host':'',
    'port':''
}
# db = SQLAlchemy(app)
db = MongoEngine(app)
migrate = Migrate(app, db)
socketio = SocketIO(app, cors_allowed_origins="*")


@socketio.on('connect')
def connect():
    # send back connected signal
    print('Client connected: ' + request.sid[:-10])
    return


@socketio.on('disconnect')
def disconnect():
    # send back connected signal
    print('Client disconnected: ' + request.sid[:-10])
    return


@socketio.on('join_session')
def join_session(data, socket_id=None):
    """
    join a session to get updates on this specific playlist
    :param data:
    :param socket_id:
    :return:
    """

    response_data = {}

    if 'token' in data:
        response_data['token'] = data['token']
        user_token = UserToken.query.filter_by(token=str(data['token'])).first()
        if user_token is not None:
            # this user already exists

            req_session = Session.query.get(id=user_token.session_id)
            session_id = req_session.id
            password = req_session.password
            name = user_token.name

            socket_id = request.sid
            user_token.socket_id = socket_id
            join_room(room=session_id, sid=socket_id)

        else:
            print('token was not found')
            return

    else:  # user sends credentials

        session_id, password, username = data['session_id'], data['password'], data['username']
        req_session: Session = Session.query.get(session_id)
        # check password
        if req_session.password != str(password):
            print(f'Password was incorrect.'
                  f'\nPass{password}')
            return

        # if the user just created this session, he may alredy
        socket_id = request.sid if not socket_id else socket_id
        user_token: UserToken = UserToken(name=username, socket_id=socket_id, session_id=session_id)
        db.session.add(user_token)
        req_session.user_tokens.append(user_token)

        response_data['token'] = user_token.token

        # database stuff
        db.session.add(req_session)
        db.session.add(user_token)

        # sockets: join the user
        join_room(room=session_id, sid=socket_id)

    # commit database changes
    db.session.commit()

    # send a list of users in this room back
    response_data['users'] = [user.serialize() for user in req_session.user_tokens]
    response_data['session'] = {
        'sessionId': req_session.id,
        'name': req_session.name,
        'userName': user_token.name
    }
    # send a message back
    emit('joined_session', response_data, room=session_id)


@socketio.on('create_session')
def create_session(data):
    password, session_name, username = data['password'], data['session_name'], data['username']
    req_session: Session = Session.query.get(name=session_name)

    if req_session.id is not None:
        # the session already exists
        # try to join?
        print('Session alredy exists')
        return

    # create session
    new_session = Session(session_name, password)

    # join this user
    join_session(data={
        'session_id': new_session.id,
        'password': password,
        'username': username
    }, user_id=request.sid)

    # return to the user that this session was created
    response_data = {
        'users': [user.serialize() for user in req_session.user_tokens]
    }
    emit('created_session', room=new_session.id)


@app.route('/')
def hello_world():
    return 'Hello World!!!'


@app.route('/session/<int:id>', methods=['POST'])
def get_session(id):
    data = request.json
    requested_session = Session.query.get_or_404(id)

    if data['password'] != requested_session.password:
        abort(500)

    # check if name is alredy taken
    existing_tokens = requested_session.user_tokens
    for t in existing_tokens:
        if t.name == data['name']:
            abort(500)

    # create a new token
    new_user_token = UserToken(
        name=data['name'],
        session_id=requested_session.id,
        token=hash(str(data['name']) + str(requested_session.id))
    )

    # persist in database
    db.session.add(requested_session)
    db.session.add(new_user_token)
    db.session.commit()

    # inform the user
    return jsonify({
        'session': Session.query.get(id).serialize(),
        'token': new_user_token.serialize()
    })


@app.route('/session/', methods=['POST'])
def create_session():
    print('Started POST request')
    # cancel if no data
    if not request.json:
        abort(400)

    data = request.json
    new_session = Session(
        name=data['name'],
        password=data['password'],
        spy_device_id=data['spy_device_id'],
        spy_token=data['spy_token']
    )

    # save to database
    db.session.add(new_session)
    db.session.commit()

    # give back everything he / she needs
    return jsonify({
        'session': new_session.serialize()
    })


@app.route('/session/<int:id>', methods=['PUT'])
def update_session(id):
    req_session: Session = Session.query.get(id)
    data = request.json

    # check if the users token is in the token list
    tokens = req_session.user_tokens
    user_authenticated = False
    for t in tokens:
        if data['token'] == t.token:
            user_authenticated = True

    if not user_authenticated:
        abort(500)

    req_session.spy_device_id = data['spy_device_id']
    req_session.spy_token = data['spy_token']





class Session(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    # session items
    name = db.Column(db.String(255))
    password = db.Column(db.String(64))
    created_on = db.Column(db.DateTime, server_default=db.func.now())

    # spotify things (spy)
    spy_token = db.Column(db.String())
    spy_device_id = db.Column(db.String())

    spy_current_song = db.Column(db.String(), nullable=True)

    user_tokens = db.relationship('UserToken', backref='session', lazy=True)

    def __init__(self, name, password, spy_token=None, spy_device_id=None, **kwargs):
        super(Session, self).__init__(**kwargs)
        self.name = name
        self.password = password
        self.spy_token = spy_token
        self.spy_device_id = spy_device_id

    def serialize(self):
        return {
            'id': self.id,
            'name': self.name,
            'spy_token': self.spy_token,
            'spy_device_id': self.spy_device_id,
            'created_on': self.created_on
        }


class UserToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String())
    name = db.Column(db.String())
    session_id = db.Column(db.Integer, db.ForeignKey('session.id'), nullable=False)
    socket_id = db.Column(db.String())

    def __init__(self, name, socket_id, session_id, **kwargs):
        super(UserToken, self).__init__(**kwargs)
        self.name = name
        # self.session_id = session_id # should be set automatically
        print(f'New UserToken generated with session_id: {self.session_id}')
        self.session_id = session_id
        self.socket_id = socket_id
        self.token = hash(str(self.name) + str(self.session_id))

    def tokenize(self):
        return self.token

    def serialize(self):
        jsonify({
            'name': self.name,
            'session_id': self.session_id
        })


upvote_users = db.Table('upvote_users',
                        db.Column('song_id', db.Integer, db.ForeignKey('song.id'), primary_key=True),
                        db.Column('user_token_id', db.Integer, db.ForeignKey('user_token.id'), primary_key=True)
                        )


class Song(db.Model):
    id = db.Column(db.String(), primary_key=True)
    session_id = db.Column(db.Integer, db.ForeignKey('session.id'), nullable=False)
    upvote_users = db.relationship('UserToken', secondary=upvote_users, lazy='subquery', backref=db.backref('songs', lazy=True))

    # spotify data
    artist = db.Column(db.String())
    title = db.Column(db.String())
    album = db.Column(db.String())
    cover_url = db.Column(db.String())

if __name__ == '__main__':
    app.run(host='192.168.178.99', port=5000)
