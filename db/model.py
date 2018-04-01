import datetime
from sqlalchemy import Column, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from passlib.apps import custom_app_context as pwd_context
from itsdangerous import (TimedJSONWebSignatureSerializer
                          as Serializer, BadSignature, SignatureExpired)


Base = declarative_base()


class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String(32), index=True)
    password_hash = Column(String(128))

    def hash_password(self, password):
        self.password_hash = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)

    def generate_auth_token(self, app, expiration=600):
        s = Serializer(app.config['SECRET_KEY'], expires_in=expiration)
        return s.dumps({'id': self.id})

    @staticmethod
    def verify_auth_token(token, app):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except SignatureExpired:
            return None
        except BadSignature:
            return None
        user = User.query.get(data['id'])
        return user


class Server(Base):
    __tablename__ = 'server'
    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    IP = Column(String(250), nullable=False)
    datetime = Column(
        DateTime, default=datetime.datetime.utcnow(),
        nullable=False)


class ping_request(Base):
    __tablename__ = 'ping_request'
    id = Column(Integer, primary_key=True)
    server_id = Column(String(250),  nullable=False)
    response_time = Column(String(250), nullable=False)
    datetime = Column(
        DateTime, default=datetime.datetime.utcnow(),
        nullable=False)


engine = create_engine('sqlite:///server_test_pings.db')
Base.metadata.create_all(engine)
DBSession = sessionmaker(bind=engine)
session = DBSession()


def make_server(name, IP, datetime=datetime.datetime.utcnow(),):
    server = session.query(Server).filter_by(name=name).first()
    print(server)
    if server is not None:
        return False

    new_server = Server(
        name=name,
        IP=IP,
        datetime=datetime)
    session.add(new_server)
    session.commit()
    server = session.query(Server).filter_by(name=name).first()
    return True


def update_server(name, IP,):
    server = session.query(Server).filter_by(name=name).first()

    if server is None:
        return False

    server.name = name
    server.datetime = server.datetime
    server.IP = IP
    session.add(server)
    session.commit()
    return True


def get_servers():
    servers = session.query(Server).all()
    return [server.name for server in servers]


def get_server(name,):
    server = session.query(Server).filter_by(name=name).first()
    if server is None:
        return False
    try:
        pings = session.query(ping_request).filter_by(server_id=server.id)
        pings_dic = []
        for i in pings.all():
            pings_dic.append({str(i.datetime): str(i.response_time)})
    except Exception as a:
        pings_dic = []
    return pings_dic


def delate_server(name,):
    server = session.query(Server).filter_by(name=name).first()

    if server is None:
        return False
    try:
        pins = session.query(ping_request).filter_by(server_id=server.id).all()
        for ping in pins:
            session.delete(ping)
    except Exception:
        pass
    session.delete(server)
    session.commit()
    return True
