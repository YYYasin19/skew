from flask import Flask, jsonify, abort, request
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_socketio import SocketIO, emit, join_room, leave_room

from app import socketio

rooms = {}


# socket things
@socketio.on('connect')
def handle_connect():
    emit('test-response', {'data': 'Welcome! You are connected'})


@socketio.on('client-message')
def handle_client_message(data):
    print('client-message: ' + data)
    client_id = request.sid
    emit('message-response', {'data': data, 'client_id': client_id}, broadcast=True)


@socketio.on('join-room')
def enter_room(data):
    user_id = request.sid
    if data['room_id'] in rooms:
        rooms[data['room_id']].append(user_id)
    else:
        rooms[data['room_id']] = [user_id]

    join_room(data['room_id'])


@socketio.on('exit-room')
def exit_room():
    user_id = request.sid
    room_id = user_get_room_id(user_id)
    leave_room(room_id)


def user_get_room_id(user_id):
    for room in rooms:
        if user_id in rooms[room]:
            return room

    return None


@socketio.on('client-message-room')
def send_room(data):
    user_id = request.sid
    room_id = 0
    for room in rooms.keys():
        if user_id in rooms[room]:
            room_id = room

    emit('message-response', {'data': data['data'], 'client_id': user_id}, room=room_id)
