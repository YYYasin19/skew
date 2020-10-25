from flask import request
from flask_socketio import join_room, emit

from app import socketio, Session, UserToken


@socketio.on('connect')
def connect():
    # send back connected signal
    print('Client connected: ' + request.sid[:-10])
    return


@socketio.on('join_session')
def join_session(data, socket_id=None):
    """
    join a session to get updates on this specific playlist
    :param data:
    :param socket_id:
    :return:
    """

    if 'token' in data:

        user_token = UserToken.query.get(token=data['token'])
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

        session_id, password, name = data['session_id'], data['password'], data['name']
        req_session: Session = Session.query.get(session_id)
        # check password
        if req_session.password != str(password):
            print(f'Password was incorrect.'
                  f'\nPass{password}')
            return

        # join the user to the session

        # if the user just created this session, he may alredy
        socket_id = request.sid if not socket_id else socket_id
        user_token: UserToken = UserToken(name=name, socket_id=socket_id)
        req_session.user_tokens.append(user_token)

        # sockets: join the user
        join_room(session_id, sid=socket_id)

    # send a list of users in this room back
    response_data = {
        'users': [user.serialize() for user in req_session.user_tokens],
        'token': user_token.token,
        'session': None
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
    }, socket_id=request.sid)

    # return to the user that this session was created
    response_data = {
        'users': [user.serialize() for user in req_session.user_tokens]
    }
    emit('created_session', room=new_session.id)
