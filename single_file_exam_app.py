# single_file_exam_app.py
from flask import Flask, render_template_string, request, redirect, url_for, flash, session, send_file
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from sentence_transformers import SentenceTransformer, util
import language_tool_python
from fpdf import FPDF
from pdfminer.high_level import extract_text
from pdf2image import convert_from_path
import pytesseract
from PIL import Image
import sqlite3, os, tempfile, re

pytesseract.pytesseract.tesseract_cmd = r'C:\\Tesseract-OCR\\tesseract.exe'  # adjust as needed

app = Flask(__name__)
app.secret_key = 'secret-key'
login_manager = LoginManager(app)
login_manager.login_view = 'login'

DATABASE = 'database.db'
UPLOAD_FOLDER = tempfile.gettempdir()
model = SentenceTransformer('all-MiniLM-L6-v2')
tool = language_tool_python.LanguageTool('en-US')

class User(UserMixin):
    def __init__(self, id, username, password, role):
        self.id = id
        self.username = username
        self.password = password
        self.role = role

def init_db():
    con = sqlite3.connect(DATABASE)
    cur = con.cursor()
    cur.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    role TEXT NOT NULL)''')
    con.commit()
    con.close()
init_db()
def get_user_by_username(username):
    con = sqlite3.connect(DATABASE)
    cur = con.cursor()
    cur.execute("SELECT id, username, password, role FROM users WHERE username=?", (username,))
    row = cur.fetchone()
    con.close()
    return User(*row) if row else None

@login_manager.user_loader
def load_user(user_id):
    con = sqlite3.connect(DATABASE)
    cur = con.cursor()
    cur.execute("SELECT id, username, password, role FROM users WHERE id=?", (user_id,))
    row = cur.fetchone()
    con.close()
    return User(*row) if row else None

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = get_user_by_username(request.form['username'])
        if user and check_password_hash(user.password, request.form['password']):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Invalid credentials')
    return render_template_string(LOGIN_HTML)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])
        role = request.form['role']
        con = sqlite3.connect(DATABASE)
        cur = con.cursor()
        cur.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", (username, password, role))
        con.commit()
        con.close()
        flash('Signup successful!')
        return redirect(url_for('login'))
    return render_template_string(SIGNUP_HTML)

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    if current_user.role == 'teacher':
        if request.method == 'POST':
            name = request.form['name']
            roll = request.form['roll']
            qp = request.files['qp']
            key = request.files['key']
            ans = request.files['ans']
            qp_path = os.path.join(UPLOAD_FOLDER, secure_filename(qp.filename))
            key_path = os.path.join(UPLOAD_FOLDER, secure_filename(key.filename))
            ans_path = os.path.join(UPLOAD_FOLDER, secure_filename(ans.filename))
            qp.save(qp_path)
            key.save(key_path)
            ans.save(ans_path)
            output_pdf = evaluate_exam_pdf(name, roll, qp_path, key_path, ans_path)
            return send_file(output_pdf, as_attachment=True)
        return render_template_string(TEACHER_DASHBOARD_HTML)
    return render_template_string(STUDENT_DASHBOARD_HTML, name=current_user.username)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

def extract_qa_from_pdf(path):
    try:
        text = extract_text(path)
        if not text.strip(): raise ValueError()
    except:
        text = ""
        for img in convert_from_path(path):
            text += pytesseract.image_to_string(img)
    qa = re.findall(r'(Q\d+):\s*(.+?)(?=\nQ\d+:|\Z)', text, re.DOTALL)
    result = {}
    for qid, content in qa:
        m = re.search(r'\[(\d+)\s*Mark[s]?\]', content, re.IGNORECASE)
        marks = int(m.group(1)) if m else 5
        clean = re.sub(r'\[\d+\s*Mark[s]?\]', '', content, flags=re.IGNORECASE).strip()
        result[qid.strip()] = {'text': clean, 'marks': marks}
    return result

def evaluate_pair(expected, student, max_marks):
    if re.fullmatch(r'[A-D]', expected.upper()) and re.fullmatch(r'[A-D]', student.upper()):
        return (max_marks if expected == student else 0), f"MCQ - {'Correct' if expected == student else 'Incorrect'}", []
    sim = util.cos_sim(model.encode(expected, convert_to_tensor=True), model.encode(student, convert_to_tensor=True)).item()
    grammar_issues = tool.check(student)
    score = max_marks * (1.0 if sim > 0.8 and len(grammar_issues)<=1 else 0.6 if sim > 0.6 else 0.4 if sim > 0.4 else 0.2)
    return round(score), f"Similarity: {round(sim*100, 1)}%. Grammar: {len(grammar_issues)} issues.", grammar_issues

def calculate_grade(score, total):
    p = (score / total) * 100
    return 'A+' if p>=90 else 'A' if p>=75 else 'B' if p>=60 else 'C' if p>=40 else 'F'

def generate_pdf(name, roll, qp, key, stu, res, score, grade):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.multi_cell(0, 10, f"Student: {name} | Roll No: {roll} | Grade: {grade} | Score: {score}\n\n")
    for qid in qp:
        pdf.set_text_color(0)
        pdf.multi_cell(0, 10, f"{qid}: {qp[qid]['text']} ({qp[qid]['marks']} marks)")
        pdf.set_text_color(0,100,0)
        pdf.multi_cell(0, 10, f"Expected: {key.get(qid, {'text':'N/A'})['text']}")
        pdf.set_text_color(200,0,0)
        pdf.multi_cell(0, 10, f"Student: {stu.get(qid, {'text':'No Answer'})['text']}")
        if qid in res:
            pdf.set_text_color(0,0,255)
            pdf.multi_cell(0, 10, f"Feedback: {res[qid]['explanation']}")
            pdf.set_text_color(0)
            pdf.cell(0, 10, f"Marks: {res[qid]['marks']}/{qp[qid]['marks']}", ln=True)
        pdf.cell(0, 5, "-----------------------------", ln=True)
    path = os.path.join(tempfile.gettempdir(), f"{roll}_result.pdf")
    pdf.output(path)
    return path

def evaluate_exam_pdf(name, roll, qp, key, stu):
    qp_data = extract_qa_from_pdf(qp)
    key_data = {k: {'text': v['text']} for k, v in extract_qa_from_pdf(key).items()}
    stu_data = {k: {'text': v['text']} for k, v in extract_qa_from_pdf(stu).items()}
    score, total = 0, sum(q['marks'] for q in qp_data.values())
    results = {}
    for qid in qp_data:
        if qid in key_data and qid in stu_data:
            marks, explanation, _ = evaluate_pair(key_data[qid]['text'], stu_data[qid]['text'], qp_data[qid]['marks'])
            results[qid] = {'marks': marks, 'explanation': explanation}
            score += marks
    grade = calculate_grade(score, total)
    return generate_pdf(name, roll, qp_data, key_data, stu_data, results, score, grade)

LOGIN_HTML = '''<!doctype html><title>Login</title><style>body{background:#e0f0ff;font-family:sans-serif;display:flex;align-items:center;justify-content:center;height:100vh}.box{background:#fff;padding:20px 30px;border-radius:10px;box-shadow:0 0 10px rgba(0,0,0,0.1)}input,select{width:100%;padding:10px;margin:10px 0;border:1px solid #ccc;border-radius:5px}</style><div class="box"><h2>Login</h2><form method=post><input name=username placeholder=Username required><input name=password type=password placeholder=Password required><button type=submit>Login</button></form><a href="/signup">Create account</a></div>'''

SIGNUP_HTML = '''<!doctype html><title>Signup</title><style>body{background:#d0ffe0;font-family:sans-serif;display:flex;align-items:center;justify-content:center;height:100vh}.box{background:#fff;padding:20px 30px;border-radius:10px;box-shadow:0 0 10px rgba(0,0,0,0.1)}input,select{width:100%;padding:10px;margin:10px 0;border:1px solid #ccc;border-radius:5px}</style><div class="box"><h2>Signup</h2><form method=post><input name=username placeholder=Username required><input name=password type=password placeholder=Password required><select name=role><option value=teacher>Teacher</option><option value=student>Student</option></select><button type=submit>Register</button></form></div>'''

TEACHER_DASHBOARD_HTML = '''<!doctype html><title>Teacher Dashboard</title><h2>Upload PDFs</h2><form method=post enctype=multipart/form-data><input name=name placeholder=Student_Name required><input name=roll placeholder=Roll_No required><br><input type=file name=qp required><br><input type=file name=key required><br><input type=file name=ans required><br><button type=submit>Evaluate</button></form><a href="/logout">Logout</a>'''

STUDENT_DASHBOARD_HTML = '''<!doctype html><title>Student Dashboard</title><h2>Welcome {{name}}</h2><p>Ask your teacher to share evaluated PDF with you.</p><a href="/logout">Logout</a>'''

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
