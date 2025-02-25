from flask import Flask, render_template, redirect, url_for, request,flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import joinedload, aliased
from sqlalchemy.sql import func, desc
from datetime import datetime
import re
from dateutil.relativedelta import relativedelta
import bcrypt
import pytz

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///dudasETSIT.db'
app.config['ENV'] = 'development'
app.config['DEBUG'] = True

# Inicialización de extensiones
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Definición de las diferentes clases de la base de datos (ver diagrama en database_structure/dudasETSIT.png)
class MessageVotes(db.Model):
    __tablename__ = 'message_votes'

    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), primary_key=True)
    message_id = db.Column(db.Integer, db.ForeignKey('message.id'), primary_key=True)
    vote_type = db.Column(db.Integer, nullable=False)  # 1 para upvote, -1 para downvote

    user = db.relationship('User', backref=db.backref('message_votes', lazy=True))
    message = db.relationship('Message', backref=db.backref('message_votes', lazy=True))

    def __repr__(self):
        return f'<MessageVotes user={self.user_id} message={self.message_id} vote_type={self.vote_type}>'
    
class IssueVotes(db.Model):
    __tablename__ = 'issue_votes'

    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), primary_key=True)
    issue_id = db.Column(db.Integer, db.ForeignKey('issue.id'), primary_key=True)
    vote_type = db.Column(db.Integer, nullable=False)  # 1 para upvote, -1 para downvote

    user = db.relationship('User', backref=db.backref('issue_votes', lazy=True))
    issue = db.relationship('Issue', backref=db.backref('issue_votes', lazy=True))

    def __repr__(self):
        return f'<IssueVotes user={self.user_id} issue={self.issue_id} vote_type={self.vote_type}>'

class IssueTags(db.Model):
    __tablename__ = 'issue_tags'

    issue_id = db.Column(db.Integer, db.ForeignKey('issue.id'), primary_key=True)
    tag_id = db.Column(db.Integer, db.ForeignKey('tag.id'), primary_key=True)

    issue = db.relationship('Issue', backref=db.backref('issue_tags', lazy=True))
    tag = db.relationship('Tag', backref=db.backref('issue_tags', lazy=True))

    def __repr__(self):
        return f'<IssueTags issue_id={self.issue_id} tag_id={self.tag_id}>'

class User(UserMixin, db.Model):
    __tablename__ = 'user'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.LargeBinary, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    messages = db.relationship('Message', backref=db.backref('user', lazy=True))
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=False)
    issues = db.relationship('Issue', backref=db.backref('user', lazy=True))

    def __repr__(self):
        return f'<User {self.username}>'

class Group(db.Model):
    __tablename__ = 'group'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), unique=True, nullable=False)
    issues = db.relationship('Issue', backref=db.backref('group', lazy=True))
    users = db.relationship('User', backref=db.backref('group', lazy=True))

    def __repr__(self):
        return f'<Group {self.name}>'


class Issue(db.Model):
    __tablename__ = 'issue'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.String(500))
    created_at = db.Column(db.DateTime, default=datetime.now())
    modified_at = db.Column(db.DateTime, default=datetime.now())
    resolved = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=False)
    messages = db.relationship('Message', backref=db.backref('issue', lazy=True))
    votes = db.Column(db.Integer, default=0)
    voters = db.relationship('User', secondary='issue_votes', backref=db.backref('voted_issues', lazy=True))
    
    @property
    def time_since_created(self):
        now = datetime.now()
        delta = relativedelta(now, self.created_at)  
        time_str = ""
        if delta.years > 0:
            time_str += f"{delta.years} año{'s' if delta.years > 1 else ''} "
        if delta.months > 0:
            time_str += f"{delta.months} mes{'es' if delta.months > 1 else ''} "
        if delta.days > 0:
            time_str += f"{delta.days} día{'s' if delta.days > 1 else ''} "
        if delta.hours > 0:
            time_str += f"{delta.hours} hora{'s' if delta.hours > 1 else ''} "
        if delta.minutes > 0:
            time_str += f"{delta.minutes} minuto{'s' if delta.minutes > 1 else ''} "
        if delta.seconds > 0 and time_str == "":
            time_str += f"{delta.seconds} segundo{'s' if delta.seconds > 1 else ''}"

        if time_str == "":
            return "muy poco"
        
        return f"{time_str.strip()}"

    def __repr__(self):
        return f'<Issue {self.title}>'

class Tag(db.Model):
    __tablename__ = 'tag'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    issues = db.relationship('Issue', secondary='issue_tags', backref=db.backref('tags', lazy=True))

    def __repr__(self):
        return f'<Tag {self.name}>'


class Message(db.Model):
    __tablename__ = 'message'

    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(500), nullable=False)
    votes = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.now())
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    issue_id = db.Column(db.Integer, db.ForeignKey('issue.id'), nullable=False)
    voters = db.relationship('User', secondary='message_votes', backref=db.backref('voted_messages', lazy=True))

# Cargar usuario
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def main():
    return redirect(url_for('login'))

# Ruta de registro
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        if not re.match(r"[^@]+@alumnos\.upm\.es$", email):
            flash("El email debe terminar con @alumnos.upm.es")
            return redirect(url_for('register'))
        password = request.form['password']
        bytes = password.encode('utf-8') 
        salt = bcrypt.gensalt() 
        hash = bcrypt.hashpw(bytes, salt) 
        group_name = request.form['group']
        group = Group.query.filter_by(name=group_name).first()
        new_user = User(username=username, email=email, password=hash, group_id=group.id)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    groups = Group.query.all()
    return render_template('register.html', groups=groups)

# Ruta de login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.checkpw(password.encode("utf-8"), user.password):
            login_user(user)
            return redirect(url_for('home', group=user.group.name))
        else:
            flash("Usuario o contraseña incorrecto")
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/home')
@login_required
def home_redirect():
    return redirect(url_for('home', group=current_user.group.name))

# Ruta de home, distinta para cada grupo (requiere autenticación)
@app.route('/<group>/home', methods=['GET', 'POST'])
@login_required
def home(group):
    group_id = Group.query.filter_by(name=group).first().id
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        tags_input = request.form['tags']
        existing_issue = Issue.query.filter_by(title=title, description=description).first()
        if existing_issue:
            flash("Ya existe una duda con el mismo título y descripción.")
        else:
            new_issue = Issue(title=title, description=description, user_id=current_user.id, group_id=group_id, created_at=datetime.now(), modified_at=datetime.now(), resolved=False)
            db.session.add(new_issue)
            tag_names = [tag.strip() for tag in tags_input.split(',')]
            tags = []
            for tag_name in tag_names:
                tag = Tag.query.filter_by(name=tag_name).first()
                if not tag:
                    tag = Tag(name=tag_name)  
                    db.session.add(tag)
                tags.append(tag)
            new_issue.tags.extend(tags)  
            print(tags)  
            db.session.commit()
            flash("Duda creada con éxito.")

    sort_field = request.args.get('sort_field', 'recientes')
    num_messages = {}
    if sort_field == 'recientes':
        issues = Issue.query.filter_by(group_id=group_id).order_by(Issue.created_at.desc()).all()
    elif sort_field == 'tendencia':
        issues = Issue.query.filter_by(group_id=group_id).order_by(Issue.votes.desc()).order_by(Issue.created_at.desc()).all()
    elif sort_field == 'activas':
        latest_message = aliased(Message)
        issues = db.session.query(Issue).join(latest_message, latest_message.issue_id == Issue.id).order_by(desc(latest_message.created_at)).filter(Issue.resolved == False).all()
    elif sort_field == 'resueltas':
        issues = Issue.query.filter_by(group_id=group_id, resolved=True).order_by(Issue.created_at.desc()).all()

    tags = {}
    for issue in issues:
        num_messages[issue.id] = len(issue.messages)  
        for tag in issue.tags:
            if tag in tags.keys():
                tags[tag] += 1
            else:
                tags[tag] = 1

    tags = dict(sorted(tags.items(), key=lambda item: item[1], reverse=True))

    return render_template('home.html', sort_field=sort_field, group=group, issues=issues, num_messages=num_messages, tags=tags)

# Ruta de dudas (requiere autenticación)
@app.route('/<group>/issue/<id>', methods=['GET', 'POST'])
@login_required
def issue(group, id):
    issue = Issue.query.filter_by(id=id).first()
    user_issue_vote = IssueVotes.query.filter_by(user_id=current_user.id, issue_id=issue.id).first()
    if user_issue_vote:
        user_issue_vote = user_issue_vote.vote_type
    messages = Message.query.filter_by(issue_id=id).order_by(Message.created_at.asc()).options(joinedload(Message.user)).all()

    message_votes = {}
    for message in messages:
        upvotes = len([vote for vote in message.message_votes if vote.vote_type == 1])
        downvotes = len([vote for vote in message.message_votes if vote.vote_type == -1])
        total_votes = upvotes - downvotes  
        message_votes[message.id] = total_votes

    sorted_messages = sorted(messages, key=lambda m: message_votes[m.id], reverse=True)

    user_votes = {}
    for message in sorted_messages:
        user_vote = MessageVotes.query.filter_by(user_id=current_user.id, message_id=message.id).first()
        if user_vote:
            user_votes[message.id] = user_vote.vote_type
        else:
            user_votes[message.id] = 0  

    if request.method == 'POST':
        if not issue.resolved:
            data = request.json
            message_content = data.get('text')
            new_message = Message(content=message_content, issue_id=id, user_id=current_user.id, created_at=datetime.now())
            db.session.add(new_message)
            db.session.commit()
    return render_template('issue.html', group=group, issue=issue, messages=sorted_messages, message_votes=message_votes, user_votes=user_votes, user_issue_vote=user_issue_vote)

# Ruta para marcar una duda como resuelta
@app.route('/<group>/issue/<id>/check')
@login_required
def check(group, id):
    issue = Issue.query.filter_by(id=id).first()
    issue.resolved = True
    db.session.commit()
    group = str(issue.group_id) + "ºGISD"
    return redirect(url_for('issue', group=group, id=issue.id))

# Ruta para marcar una duda como no resuelta
@app.route('/<group>/issue/<id>/uncheck')
@login_required
def uncheck(group, id):
    issue = Issue.query.filter_by(id=id).first()
    issue.resolved = False
    db.session.commit()
    group = str(issue.group_id) + "ºGISD"
    return redirect(url_for('issue', group=group, id=issue.id))

@app.route('/<group>/issue/<issueid>/voteup')
@login_required
def voteup_issue(group, issueid):
    issue = Issue.query.get(issueid)
    vote = IssueVotes.query.filter_by(user_id=current_user.id, issue_id=issueid).first()

    if issue:
        if not vote:  
            new_vote = IssueVotes(user_id=current_user.id, issue_id=issueid, vote_type=1)
            issue.votes += 1
            db.session.add(new_vote)
        elif vote.vote_type == 1:  
            issue.votes -= 1
            db.session.delete(vote)
        elif vote.vote_type == -1: 
            vote.vote_type = 1
            issue.votes += 2  

        db.session.commit()

    return redirect(url_for('issue', group=group, id=issue.id))


@app.route('/<group>/issue/<issueid>/votedown')
@login_required
def votedown_issue(group, issueid):
    issue = Issue.query.get(issueid)
    vote = IssueVotes.query.filter_by(user_id=current_user.id, issue_id=issueid).first()

    if issue:
        if not vote:  
            new_vote = IssueVotes(user_id=current_user.id, issue_id=issueid, vote_type=-1)
            issue.votes -= 1
            db.session.add(new_vote)
        elif vote.vote_type == -1:  
            issue.votes += 1
            db.session.delete(vote)
        elif vote.vote_type == 1: 
            vote.vote_type = -1
            issue.votes -= 2  

        db.session.commit()

    return redirect(url_for('issue', group=group, id=issue.id))

@app.route('/<group>/issue/<id>/<messageid>/voteup')
@login_required
def voteup(group, id, messageid):
    message = Message.query.get(messageid)
    vote = MessageVotes.query.filter_by(user_id=current_user.id, message_id=messageid).first()

    if message:
        if not vote:  
            new_vote = MessageVotes(user_id=current_user.id, message_id=messageid, vote_type=1)
            message.votes += 1
            db.session.add(new_vote)
        elif vote.vote_type == 1:  
            message.votes -= 1
            db.session.delete(vote)
        elif vote.vote_type == -1: 
            vote.vote_type = 1
            message.votes += 2  

        db.session.commit()

    return redirect(url_for('issue', group=group, id=id))


@app.route('/<group>/issue/<id>/<messageid>/votedown')
@login_required
def votedown(group, id, messageid):
    message = Message.query.get(messageid)
    vote = MessageVotes.query.filter_by(user_id=current_user.id, message_id=messageid).first()

    if message:
        if not vote:  
            new_vote = MessageVotes(user_id=current_user.id, message_id=messageid, vote_type=-1)
            message.votes -= 1
            db.session.add(new_vote)
        elif vote.vote_type == -1:  
            message.votes += 1
            db.session.delete(vote)
        elif vote.vote_type == 1: 
            vote.vote_type = -1
            message.votes -= 2

        db.session.commit()

    return redirect(url_for('issue', group=group, id=id))


# Ruta de logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(port=5001)