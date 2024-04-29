import flask
from flask import Flask, render_template, request, redirect, url_for
import os
import requests
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.utils import secure_filename  

VIRUSTOTAL_API_KEY = '0d98247dba07607e9ace201198fb99f625b05c4f8cdfddb80e57711a78b65d49'
MAX_CONTENT_LENGTH = 5 * 1024 * 1024  

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

ALLOWED_EXTENSIONS = {'txt', 'pdf', 'docx'}  #

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        if 'file' not in request.files:
            return redirect(url_for('failure'))

        file = request.files['file']
        if file.filename == '' or not allowed_file(file.filename):
            return redirect(url_for('failure'))

        try:
            file_data = file.read()  

            secure_file_name = secure_filename(file.filename)

            # API request to VirusTotal
            headers = {'x-apikey': VIRUSTOTAL_API_KEY}
            url = 'https://www.virustotal.com/api/v3/files'
            response = requests.post(
                url, headers=headers, files={'file': (secure_file_name, file_data)}
            )

            if response.status_code == 200:
                data = response.json()

                if is_file_safe(data):
                    return redirect(url_for('success'))
                else:
                    return redirect(url_for('failure'))
            else:
                return redirect(url_for('failure'))

        except requests.exceptions.RequestException:
            return redirect(url_for('failure'))

    return render_template('index.html')

@app.route('/success')
def success():
    return render_template('success.html')

@app.route('/failure')
def failure():
    return render_template('failure.html')

@app.errorhandler(RequestEntityTooLarge)
def handle_large_file_error(e):
    return redirect(url_for('failure'))

# Improved function to determine file safety based on VirusTotal response
def is_file_safe(data):
    positive_detections = 0

    # Check for positive detections 
    for scan_name, scan_result in data.get('data', {}).get('attributes', {}).get('last_analysis_results', {}).items():
        if scan_result['category'] == 'malicious':
            positive_detections += 1

    return positive_detections == 0

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0')
