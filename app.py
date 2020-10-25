from flask import Flask, request, jsonify
from flask_socketio import SocketIO, join_room, emit, rooms

from models import Session, User, Song
from db import initialize_db

from dotenv import load_dotenv, find_dotenv
import os
load_dotenv(find_dotenv())

app = Flask(__name__)
app.config['MONGODB_SETTINGS'] = {
    'host': os.getenv('MONGODB_URL') # this should be in you .env-File
}

initialize_db(app)
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


@socketio.on('create_session')
def create_session(data):
    password, session_name = data['password'], data['session_name']

    # catch: session with that name already exists

    new_session: Session = Session(name=session_name, password=password)
    new_session.save()

    # return to the user that this session was created
    response_data = {
        'session': new_session.to_json()
    }
    print(f'Sending response: {response_data}')

    emit('created_session', response_data)


def send_session_update(session: Session):
    """
    Sends an update of the current session to all users of this session (room)
    :param session: Session object from the database
    """
    """
    import json

    session_dict = json.loads(session.to_json())
    for song in session_dict['songs']:
        song['upvote_users'] = len(song['upvote_users'])
    

    emit('updated_session', json.dumps(session_dict), room=str(session.id))
    """
    current_rooms = rooms()
    for song in session.songs:
        song.upvote_users = len(song.upvote_users)
    session_id = str(session.id)
    emit('updated_session', session.to_json(), room=str(session.id))


@socketio.on('add_song')
def add_song(data):
    """
    This method adds a song to the current session.
    :param data: Contains auth-Data (namely a user token), a session id, and a song
    :return: None
    """

    # STEP 1: Extraxt data
    token = data['token']
    new_song = data['song']

    if (not token) or (not new_song):
        # send_error_message()
        return

    # STEP 2: Get session and check auth
    user = User.objects.get(id=token)

    # STEP 3: Update session data
    session = Session.objects.get(id=str(user.session.id))
    songs = session.songs

    # check if our song in songs already
    s: Song
    already_included = False
    for s in songs:
        if str(s.song_data['uri']) == str(new_song['uri']):
            already_included = True
            break

    if not already_included:
        # create this song and add to session
        new_song_obj = Song()
        new_song_obj.song_data = new_song
        new_song_obj.upvote_users.append(token)
        session.songs.append(new_song_obj)
        session.save()

        # STEP 4: Send out update -- if there was a change
        send_session_update(session)


@socketio.on('update_vote')
def update_vote(data):
    """
    This method updates a song. Because this is no fundamental change to the session, the only authentication needed is
    the required token for the session.
    :param data: Should contain the token (to find user and session) as well as the targeted song
    :return:
    """

    # STEP 1: Get the right data
    token = data['token']
    song_uri = data['uri']

    # STEP 2: Check if authorized for action
    user = User.objects.get(id=token)
    session = user.session

    # STEP 3: Find the song
    req_song: Song
    for song in session.songs:
        if str(song['song_data']['uri']) == song_uri:
            req_song = song
            break

    if req_song is None:
        # there must be some error
        return

    # STEP 4: Increment upvotes if not voted yet, otherwise decrement
    u: User
    user_already_voted = False
    for u in req_song.upvote_users:
        if str(u) == str(token):
            user_already_voted = True
            break

    if user_already_voted:
        # remove his vote
        req_song.upvote_users.remove(token)
    else:
        # add this user
        req_song.upvote_users.append(token)

    # req_song.save()
    session.save()

    # STEP 5: Update the session for all users with data from the database
    send_session_update(session)


@socketio.on('update_session')
def update_session(data):
    # extract information
    token = data['token']
    session_data = data['session']
    current_playback_data = session_data['current_playback'] if 'current_playback' in session_data else ""
    # if current_playback_data:
    #     session_data['current_playback'] = str(current_playback_data)
    session_id = session_data['_id']['$oid']

    # get the user, to check if he is in this session
    user = User.objects.get(id=token)
    if str(user.session.id) != str(session_id):
        emit('error_message', {'message': 'User not found or authorized for this update'})
        return

    current_rooms = rooms()

    # get the session
    session = Session.objects.get(id=session_id)
    session['current_playback'] = current_playback_data if current_playback_data else ""
    session.save()

    # send an update to everyone about this session
    send_session_update(session)


@socketio.on('join_session')
def join_session(data):
    """
    Client joins a specific session.
    This results in joining a socket room where updates to this session are provided.
    :param data: has keys ['token'] or ['session_name', 'username', 'password']
    :return: Ack-Signal with Token
    """

    final_user: User

    if 'token' in data:

        # Get Authentication token
        token = str(data['token'])

        # find user with this token
        user = User.objects.get(id=token)
        if user is None:
            send_error_msg('No user for your authentication token was found.')
            return

        # Update this users socket
        user.socket_id = str(request.sid)

        final_user = user

    elif 'session_name' in data and 'username' in data and 'password' in data:

        # extract data
        session_name, password, username = data['session_name'], data['password'], data['username']

        # find session
        session = Session.objects.get(name=session_name)
        if session is None:
            send_error_msg(f'There is no session with the name {session_name} currently. Create one?')
            return

        # check password
        if str(session.password) != str(password):
            send_error_msg('The provided password is wrong. Check case-sensitity!')
            return

        # check if there is a user with this name for this session
        # if there is one: reject this users request to join (no duplicates)
        users = User.objects(username__exact=username)

        for u in users:
            if (u.session.id) == session.id:
                # reject join request
                send_error_msg(f'A user with the name {username} already exists for this session.')
                return

        # create a new user for this session
        new_user = User(
            username=username,
            session=session,
            socket_id=str(request.sid)
        )
        new_user.save()

        final_user = new_user
    else:
        send_error_msg('The provided authentication data was not sufficient for joining this session.'
                       'Either send an already created authentication token '
                       'or a valid combination of username, password and session name.')
        return

    # join the final user to the room
    join_room(room=str(final_user.session.id), sid=request.sid)

    # send the user his token -> handle with callback on client-side
    return str(final_user.id)


def send_error_msg(msg, room=None):
    """
    sends an error message to all clients (of a specific room)
    :param room: If specified, the message will be sent for a specific room only
    :param msg: string message. The key is 'message'
    :return: None
    """
    emit('error_message', {
        'message': msg
    }, room=room)


@socketio.on('join_session')
def join_session(data):
    """
    join a session to get updates on this specific playlist
    :param data:
    :param socket_id:
    :return:
    """
    # TODO: This method needs to be rewritten
    # The user should only get his token for later queries -> with that he can confirm, that the join was successfull
    # An update should be pushed out, so he has all the data he needs

    response_data = {

    }

    # user was already authenticated, just wants to rejoin
    if 'token' in data:
        respond_token = data['token']  # send his token back

        # find the user
        req_user: User = User.objects.get(id=data['token'])
        if req_user is None:
            emit('error_message', {'message': 'The token is invalid. There is no such user.'})
            return

        # update this users socket id
        req_session = req_user.session
        req_user.socket_id = str(request.sid)
        req_user.save()

        # join this user to the room
        join_room(room=str(req_session.id), sid=str(req_user.socket_id))

    else:
        session_name, password, username = data['session_name'], data['password'], data['username']
        req_session: Session = Session.objects.get(name=session_name)

        if not req_session:
            # this session does not exist
            return

        if password != req_session.password:
            print('Password was incorrect')
            emit('error_message', {'message': 'Password was incorrect'})
            return

        socket_id = str(request.sid)
        new_user: User = User(username=username,
                              session=req_session,
                              socket_id=socket_id)
        new_user.save()

        # give the user his id, so he can tell us lateron who he is
        respond_token = str(new_user.id)
        join_room(room=str(new_user.session.id), sid=str(socket_id))

    # fill response data
    response_data['session'] = req_session.to_json()

    emit('send_token', {'token': respond_token})  # only to user
    # send_session_update(req_session)
    emit('joined_session', response_data, room=str(req_session.id))  # all in group


# models


if __name__ == '__main__':
    app.run(host='192.168.178.99', port=5000)
