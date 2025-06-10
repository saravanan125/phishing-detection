from flask import Flask, request, render_template, redirect, url_for, session, flash
import numpy as np
import pickle
import logging
import sqlite3
from datetime import datetime
import os
from urllib.parse import urlparse
from feature import FeatureExtraction

# Set up logging
logging.basicConfig(level=logging.DEBUG)

# Load the pre-trained model
model_path = "C:/Users/sarav/Downloads/Phishing Website Detection and Defence System/pickle"
try:
    with open(model_path, "rb") as file:
        gbc = pickle.load(file)
except Exception as e:
    logging.error(f"Error loading model: {e}")
    gbc = None

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Generate a random secret key for session management

# Database setup for defense system
import os
import sqlite3

def init_db():
    db_path = 'phishing_defense.db'
    print(f"Database will be created at: {os.path.abspath(db_path)}")
    
    try:
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()
            # Create tables if they don't exist
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS reported_urls (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    notes TEXT
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS blocked_attempts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    safety_score REAL NOT NULL
                )
            ''')
            
            conn.commit()
    except Exception as e:
        logging.error(f"Error initializing database: {e}")

# Initialize database
init_db()

def is_valid_url(url):
    """Validate the URL format."""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

def should_block_url(safety_score):
    """Determine if a URL should be blocked based on safety score."""
    return safety_score < 0.5

def get_phishing_indicators(features):
    """Extract phishing indicators from features."""
    feature_names = [
        "UsingIP", "LongURL", "ShortURL", "Symbol@", "Redirecting//", 
        "PrefixSuffix-", "SubDomains", "HTTPS", "DomainRegLen", "Favicon", 
        "NonStdPort", "HTTPSDomainURL", "RequestURL", "AnchorURL", "LinksInScriptTags", 
        "ServerFormHandler", "InfoEmail", "AbnormalURL", "WebsiteForwarding", "StatusBarCust", 
        "DisableRightClick", "UsingPopupWindow", "IframeRedirection", "AgeofDomain", 
        "DNSRecording", "WebsiteTraffic", "PageRank", "GoogleIndex", "LinksPointingToPage", 
        "StatsReport"
    ]
    
    feature_descriptions = {
        "UsingIP": "Uses an IP address in the URL instead of a domain name",
        "LongURL": "Unusually long URL that might hide the true destination",
        "ShortURL": "Uses a URL shortening service which can hide the destination",
        "Symbol@": "Contains @ symbol which can lead to URL confusion",
        "Redirecting//": "Contains multiple forward slashes indicating possible redirection",
        "PrefixSuffix-": "Uses hyphens to make the domain look legitimate",
        "SubDomains": "Has an excessive number of subdomains",
        "HTTPS": "Missing secure HTTPS connection",
        "DomainRegLen": "Domain registered for a very short period",
        "Favicon": "Favicon doesn't match with domain",
        "NonStdPort": "Uses non-standard port numbers",
        "HTTPSDomainURL": "HTTPS token in domain part of URL",
        "RequestURL": "Request resources from external domains",
        "AnchorURL": "Links on page point to suspicious domains",
        "LinksInScriptTags": "Links in script tags pointing to external sources",
        "ServerFormHandler": "Form actions submitting to external domains",
        "InfoEmail": "Abnormal use of mailto: function",
        "AbnormalURL": "URL doesn't match with title or content",
        "WebsiteForwarding": "Excessive redirections",
        "StatusBarCust": "Status bar customization to hide true URL",
        "DisableRightClick": "Disables right-click functionality",
        "UsingPopupWindow": "Uses suspicious popup windows",
        "IframeRedirection": "Uses hidden iframes for redirection",
        "AgeofDomain": "Very recently registered domain",
        "DNSRecording": "Missing DNS records",
        "WebsiteTraffic": "Very low website traffic",
        "PageRank": "Low page rank score",
        "GoogleIndex": "Not indexed by Google",
        "LinksPointingToPage": "Few or no other sites link to this page",
        "StatsReport": "Poor statistics or reporting"
    }
    
    suspicious_indicators = []
    
    # Check which features indicate phishing
    for i, feature in enumerate(features):
        if i < len(feature_names):
            if feature == 1 and feature_names[i] not in ["HTTPS", "GoogleIndex"]:  # Most features: 1 = suspicious
                suspicious_indicators.append(feature_descriptions[feature_names[i]])
            elif feature == 0 and feature_names[i] in ["HTTPS", "GoogleIndex"]:  # These features: 0 = suspicious
                suspicious_indicators.append(feature_descriptions[feature_names[i]])
    
    return suspicious_indicators

@app.route("/", methods=["GET", "POST"])
def index():
    """Main page for URL phishing detection."""
    if request.method == "POST":
        url = request.form.get("url", "").strip()
        if not url or not is_valid_url(url):
            flash("Invalid URL format. Please enter a valid URL.")
            return render_template("index.html", xx=-1, error="Invalid URL format.")

        try:
            obj = FeatureExtraction(url)
            x = np.array(obj.getFeaturesList()).reshape(1, 30)
            
            if gbc:
                y_pred = gbc.predict(x)[0]
                y_pro_phishing = gbc.predict_proba(x)[0, 0]  # Probability of phishing
                y_pro_non_phishing = gbc.predict_proba(x)[0, 1]  # Probability of legitimate
                
                # Store URL information in session for defense system
                session['url'] = url
                session['safety_score'] = float(y_pro_non_phishing)
                session['features'] = obj.getFeaturesList()
                
                # Check if URL should be blocked
                if should_block_url(y_pro_non_phishing):
                    # Log the blocked attempt
                    try:
                        with sqlite3.connect('phishing_defense.db') as conn:
                            cursor = conn.cursor()
                            cursor.execute(
                                "INSERT INTO blocked_attempts (url, timestamp, safety_score) VALUES (?, ?, ?)",
                                (url, datetime.now().isoformat(), y_pro_non_phishing)
                            )
                            conn.commit()
                    except Exception as e:
                        logging.error(f"Error logging blocked attempt: {e}")
                    
                    # Redirect to warning page
                    return redirect(url_for('warning'))
                
                pred = f"It is {y_pro_non_phishing * 100:.2f}% safe to go."
                return render_template('index.html', xx=round(y_pro_non_phishing, 2), url=url, pred=pred)
            else:
                flash("Model not loaded. Please try again later.")
                return render_template("index.html", xx=-1, error="Model not loaded.")
        except Exception as e:
            logging.error(f"Error processing URL: {e}")
            flash("An error occurred while processing the URL. Please try again.")
            return render_template("index.html", xx=-1, error="An error occurred while processing the URL.")

    return render_template("index.html", xx=-1)
@app.route('/learn')
def learn():
    """Display educational information about phishing."""
    return render_template('learn.html')
@app.route('/settings')
def settings():
    """Display and manage user settings."""
    return render_template('settings.html')

@app.route('/warning')
def warning():
    """Display warning for potentially dangerous URLs."""
    url = session.get('url', '')
    safety_score = session.get('safety_score', 0.0)
    
    features = session.get('features', [])
    
    if not url:
        flash("No URL found in session. Please check a URL first.")
        return redirect(url_for('index'))
    
    # Get phishing indicators based on feature extraction
    try:
        suspicious_indicators = get_phishing_indicators(features)
    except Exception as e:
        logging.error(f"Error extracting indicators: {e}")
        suspicious_indicators = ["URL has suspicious characteristics"]
    safety_score = max(safety_score, 0.01)  # Ensure it's at least 0.01
    safety_score = safety_score * 100  # Convert to percentage
    
    print(f"Final Safety Score: {safety_score}")
    
    return render_template(
        'warning.html', 
        url=url, 
        safety_score=safety_score,  # Convert to percentage
        indicators=suspicious_indicators
    )

@app.route('/report', methods=['POST'])
def report():
    """Handle user reports of phishing URLs."""
    url = request.form.get('url', '')
    notes = request.form.get('notes', '')
    
    if not url or not is_valid_url(url):
        flash('Invalid URL format. Please enter a valid URL.')
        return redirect(url_for('index'))
    
    try:
        with sqlite3.connect('phishing_defense.db') as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO reported_urls (url, timestamp, notes) VALUES (?, ?, ?)",
                (url, datetime.now().isoformat(), notes)
            )
            conn.commit()
    except Exception as e:
        logging.error(f"Error logging reported URL: {e}")
    
    flash('Thank you for reporting this URL. Your report helps improve our phishing detection system.')
    return redirect(url_for('index'))

@app.route('/education')
def education():
    """Display educational information about phishing."""
    return render_template('education.html')

@app.route('/dashboard')
def dashboard():
    """Admin dashboard to view reported URLs and blocked attempts."""
    try:
        with sqlite3.connect('phishing_defense.db') as conn:
            cursor = conn.cursor()
            
            # Get recent blocked attempts
            cursor.execute("SELECT url, timestamp, safety_score FROM blocked_attempts ORDER BY timestamp DESC LIMIT 10")
            blocked = cursor.fetchall()
            
            # Format safety_score as a percentage
            blocked = [
                (url, timestamp, round(safety_score * 100, 2))  # Convert to percentage and round to 2 decimal places
                for url, timestamp, safety_score in blocked
            ]
            
            # Get recent reports
            cursor.execute("SELECT url, timestamp, notes FROM reported_urls ORDER BY timestamp DESC LIMIT 10")
            reports = cursor.fetchall()
            
            # Get statistics
            cursor.execute("SELECT COUNT(*) FROM blocked_attempts")
            total_blocked = cursor.fetchone()[0]
            
            # Debug: Print the total blocked URLs
            print(f"Total Blocked URLs: {total_blocked}")
            
            cursor.execute("SELECT COUNT(*) FROM reported_urls")
            total_reports = cursor.fetchone()[0]
    except Exception as e:
        logging.error(f"Error fetching dashboard data: {e}")
        blocked = []
        reports = []
        total_blocked = 0
        total_reports = 0
    
    return render_template(
        'dashboard.html',
        blocked=blocked,
        reports=reports,
        total_blocked=total_blocked,
        total_reports=total_reports
    )

if __name__ == "__main__":
    app.run(debug=True)