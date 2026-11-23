
import re
import joblib
import streamlit as st
import pandas as pd
from pathlib import Path
import sqlite3
# -----------------------------
# PAGE CONFIGURATION
# -----------------------------

BASE_DIR = Path(__file__).resolve().parent
MODEL_PATH = BASE_DIR / "models" / "scam_detector_v4.pkl"

# SQLite database location
DB_PATH = BASE_DIR / "scamsathi_history.db"


def init_db():
    conn = sqlite3.connect(DB_PATH)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS analysis_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            message TEXT,
            prediction TEXT,
            risk TEXT,
            spam_score REAL
        )
    """)

    conn.commit()
    conn.close()


def save_analysis(record):
    conn = sqlite3.connect(DB_PATH)

    conn.execute("""
        INSERT INTO analysis_history
        (message, prediction, risk, spam_score)
        VALUES (?, ?, ?, ?)
    """, (
        record["Message"],
        record["Prediction"],
        record["Risk"],
        record["Spam Score"]
    ))

    conn.commit()
    conn.close()


def load_history():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    rows = conn.execute("""
        SELECT message, prediction, risk, spam_score
        FROM analysis_history
        ORDER BY id DESC
    """).fetchall()

    conn.close()

    return [
        {
            "Message": row["message"],
            "Prediction": row["prediction"],
            "Risk": row["risk"],
            "Spam Score": row["spam_score"]
        }
        for row in rows
    ]


def clear_database_history():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DELETE FROM analysis_history")
    conn.commit()
    conn.close()


# Create database table
init_db()

st.set_page_config(
    page_title="ScamSathi | AI Protection",
    page_icon="🛡️",
    layout="wide"
)

# -----------------------------
# CUSTOM CSS
# -----------------------------


# -----------------------------
# CUSTOM PROFESSIONAL DESIGN
# -----------------------------

st.markdown("""
<style>

/* Main application background */
.stApp {
    background: linear-gradient(
        135deg,
        #08111f 0%,
        #101d33 55%,
        #0b1730 100%
    );
    color: #f8fafc;
}

/* Main content spacing */
.block-container {
    max-width: 1250px;
    padding-top: 2rem;
    padding-bottom: 3rem;
}

/* Sidebar */
[data-testid="stSidebar"] {
    background: #101c30;
    border-right: 1px solid #263b59;
}

[data-testid="stSidebar"] * {
    color: #e2e8f0 !important;
}

/* Headings */
h1, h2, h3 {
    color: #f8fafc !important;
    font-weight: 750 !important;
}

p, label, .stMarkdown {
    color: #dbeafe;
}

/* Text area - IMPORTANT VISIBILITY FIX */

/* FORCE MESSAGE INPUT TEXT TO BE VISIBLE */

div[data-testid="stTextArea"] textarea,
[data-baseweb="textarea"] textarea,
.stTextArea textarea {
    background-color: #ffffff !important;
    color: #111827 !important;
    -webkit-text-fill-color: #111827 !important;
    caret-color: #0284c7 !important;
    font-size: 18px !important;
    font-weight: 600 !important;
    font-family: Arial, sans-serif !important;
    opacity: 1 !important;
    border: 2px solid #38bdf8 !important;
    border-radius: 12px !important;
    padding: 14px !important;
}

/* INPUT PLACEHOLDER */
div[data-testid="stTextArea"] textarea::placeholder {
    color: #64748b !important;
    -webkit-text-fill-color: #64748b !important;
    opacity: 1 !important;
}

/* TEXT SELECTION */
div[data-testid="stTextArea"] textarea::selection {
    background-color: #93c5fd !important;
    color: #111827 !important;
}

/* Text area placeholder */
[data-baseweb="textarea"] textarea::placeholder {
    color: #64748b !important;
    opacity: 1 !important;
}

/* Other input fields */
[data-baseweb="input"] input {
    background-color: #f8fafc !important;
    color: #111827 !important;
    caret-color: #0284c7 !important;
    border-radius: 10px !important;
}

/* Dropdowns */
[data-baseweb="select"] > div {
    background-color: #f8fafc !important;
    color: #111827 !important;
}

/* Buttons */
.stButton > button {
    background: linear-gradient(
        90deg,
        #0284c7,
        #2563eb
    ) !important;
    color: white !important;
    border: none !important;
    border-radius: 10px !important;
    padding: 12px 20px !important;
    font-weight: 700 !important;
    transition: 0.2s ease;
}

.stButton > button:hover {
    background: linear-gradient(
        90deg,
        #0369a1,
        #1d4ed8
    ) !important;
    border: 1px solid #7dd3fc !important;
}

/* Metric cards */
[data-testid="stMetric"] {
    background: #172a45;
    padding: 20px;
    border: 1px solid #294565;
    border-radius: 14px;
}

/* Metric labels */
[data-testid="stMetricLabel"] {
    color: #93c5fd !important;
}

/* Metric values */
[data-testid="stMetricValue"] {
    color: #38bdf8 !important;
    font-weight: 800 !important;
}

/* Alerts and messages */
[data-testid="stAlert"] {
    border-radius: 12px;
}

/* Horizontal divider */
hr {
    border-color: #29415f !important;
}

/* Dataframes */
[data-testid="stDataFrame"] {
    border: 1px solid #29415f;
    border-radius: 12px;
    overflow: hidden;
}

/* Sidebar radio buttons */
[data-testid="stSidebar"] [role="radiogroup"] {
    gap: 10px;
}

/* Smooth card appearance */
[data-testid="stVerticalBlockBorderWrapper"] {
    border-radius: 14px;
}

/* Improve information and success message visibility */
[data-testid="stAlert"] {
    background: #172d49 !important;
    color: #f8fafc !important;
    border: 1px solid #38bdf8 !important;
    border-radius: 12px !important;
}

[data-testid="stAlert"] p,
[data-testid="stAlert"] div,
[data-testid="stAlert"] span {
    color: #f8fafc !important;
}

/* Improve text area visibility */
[data-baseweb="textarea"] textarea {
    background: #ffffff !important;
    color: #111827 !important;
    caret-color: #0284c7 !important;
    font-size: 16px !important;
    border: 2px solid #38bdf8 !important;
}

/* Improve placeholder readability */
[data-baseweb="textarea"] textarea::placeholder {
    color: #64748b !important;
    opacity: 1 !important;
}

/* Improve warning and error message readability */
[data-testid="stAlert"] {
    background-color: #172a45 !important;
    color: #ffffff !important;
    border: 1px solid #38bdf8 !important;
}

[data-testid="stAlert"] p,
[data-testid="stAlert"] div,
[data-testid="stAlert"] span {
    color: #ffffff !important;
}

</style>
""", unsafe_allow_html=True)

# -----------------------------
# LOAD TRAINED MODEL
# -----------------------------

@st.cache_resource
def load_model():
    artifact = joblib.load(MODEL_PATH)
    return artifact

if not MODEL_PATH.exists():
    st.error("Model not found. Run train_model.py first.")
    st.stop()

try:
    artifact = load_model()
    model = artifact["model"]
    accuracy = artifact["accuracy"]
    dataset_size = artifact["dataset_size"]
except Exception as error:
    st.error(f"Unable to load model: {error}")
    st.stop()

# -----------------------------
# SESSION HISTORY
# -----------------------------

if "history" not in st.session_state:
    st.session_state.history = load_history()

# -----------------------------
# CATEGORY DETECTION
# -----------------------------


def detect_category(message):
    text = message.lower()

    categories = {
        "UPI / Payment": [
            "upi", "payment", "transaction",
            "refund", "bank transfer", "cashback",
            "credited", "debited"
        ],

        "OTP / Account": [
            "otp", "verification code",
            "verify account", "kyc",
            "password", "pin"
        ],

        "Banking / Account Security": [
            "bank account", "account blocked",
            "account suspended", "account will be blocked",
            "account will be closed", "kyc expired",
            "bank alert"
        ],

        "Fake Job Offer": [
            "job offer", "work from home",
            "recruitment", "registration fee",
            "processing fee", "job vacancy",
            "earn daily", "salary offer"
        ],

        "Lottery / Prize": [
            "lottery", "won a prize",
            "congratulations", "winner",
            "reward", "free money", "cash prize"
        ],

        "Phishing / Link": [
            "click here", "http://", "https://",
            "www.", "login", "verify now"
        ],

        "Delivery / Shopping": [
            "parcel", "delivery", "shipped",
            "order confirmation", "tracking"
        ]
    }

    found = []

    for category, keywords in categories.items():
        if any(word in text for word in keywords):
            found.append(category)

    return found or ["General Message"]

# -----------------------------
# WARNING SIGN DETECTION
# -----------------------------


def detect_warnings(message):
    text = message.lower()
    warnings = []

    rules = {
        "Urgent language": [
            "immediately", "urgent", "act now",
            "limited time", "last chance"
        ],

        "Prize or reward claim": [
            "won", "prize", "reward",
            "free money", "lottery"
        ],

        "Account verification": [
            "verify account", "account blocked",
            "account suspended", "kyc expired"
        ],

        "Sensitive information request": [
            "share otp", "send otp",
            "share your pin", "send your pin",
            "share password", "enter your password"
        ],

        "Suspicious job offer": [
            "registration fee", "processing fee",
            "pay to confirm your job",
            "pay a fee to secure your job",
            "refundable fee", "job offer fee"
        ],

        "Suspicious payment request": [
            "pay now", "transfer money",
            "send money", "pay immediately"
        ],

        "Account threat": [
            "account will be blocked",
            "account will be closed",
            "connection will be disconnected"
        ]
    }

    # Check warning phrases
    for reason, keywords in rules.items():
        if any(word in text for word in keywords):
            warnings.append(reason)

    # Detect web links
    if re.search(r"https?://|www\.", text):
        warnings.append("Contains a web link")

    # Avoid flagging ordinary payment confirmations
    safe_payment_phrases = [
        "payment was successful",
        "payment is successful",
        "payment received",
        "transaction was successful",
        "transaction successful",
        "payment has been received",
        "recharge was successful",
        "bill payment is confirmed"
    ]

    if any(phrase in text for phrase in safe_payment_phrases):
        warnings = [
            warning for warning in warnings
            if warning != "Suspicious payment request"
        ]

    if not warnings:
        warnings.append(
            "No warning phrases detected by the keyword rules."
        )

    return warnings

# -----------------------------
# SIDEBAR
# -----------------------------

st.sidebar.title("🛡️ ScamSathi")
st.sidebar.caption("AI Digital Safety Assistant")

page = st.sidebar.radio(
    "Navigation",
    [
        "Dashboard",
        "Message Analyzer",
        "Analysis History",
        "About Project"
    ]
)

st.sidebar.divider()

st.sidebar.metric(
    "Training Messages",
    f"{dataset_size:,}"
)

st.sidebar.metric(
    "Internal Test Accuracy",
    f"{accuracy * 100:.2f}%"
)

st.sidebar.caption(
    "Educational prototype. Not a certified fraud detector."
)

# -----------------------------
# DASHBOARD
# -----------------------------


# -----------------------------
# PROFESSIONAL DASHBOARD
# -----------------------------

if page == "Dashboard":

    st.markdown("""
    <div style="
        background: linear-gradient(120deg,#12345a,#075985);
        padding: 35px;
        border-radius: 18px;
        border: 1px solid #38bdf8;
        margin-bottom: 25px;
    ">
        <h1 style="color:white; font-size:42px;">
            🛡️ ScamSathi
        </h1>
        <h3 style="color:#bae6fd;">
            Your Digital Safety Intelligence Platform
        </h3>
        <p style="color:#e0f2fe; font-size:16px;">
            AI-powered screening of suspicious messages
            using Natural Language Processing and Machine Learning.
        </p>
    </div>
    """, unsafe_allow_html=True)

    st.subheader("📊 System Overview")

    c1, c2, c3 = st.columns(3)

    with c1:
        st.metric("System Status", "ACTIVE")

    with c2:
        st.metric("Training Messages", f"{dataset_size:,}")

    with c3:
        st.metric("Internal Test Accuracy", f"{accuracy * 100:.2f}%")

    st.divider()

    st.subheader("🔍 Digital Message Protection")

    st.write(
        "Analyze suspicious messages and identify "
        "patterns associated with safe, spam and scam messages."
    )

    left, right = st.columns([2, 1])

    with left:
        st.info(
            "Navigate to Message Analyzer to check an SMS "
            "or suspicious text message."
        )

    with right:
        st.success(
            "Machine Learning Model Loaded"
        )

    st.subheader("✨ Available Features")

    f1, f2, f3 = st.columns(3)

    with f1:
        st.markdown("### 🧠 AI Analysis")
        st.caption("Machine learning message classification")

    with f2:
        st.markdown("### 🚨 Risk Screening")
        st.caption("Spam score and warning indicators")

    with f3:
        st.markdown("### 📈 History")
        st.caption("Review your previous message analyses")

    st.divider()

    st.caption(
        "ScamSathi | AI/ML Academic Portfolio Project"
    )

# -----------------------------
# MESSAGE ANALYZER
# -----------------------------

elif page == "Message Analyzer":

    st.title("🔍 AI Message Analyzer")

    st.write(
        "Enter an SMS or text message for machine learning analysis."
    )

    message = st.text_area(
        "Your message",
        key="analysis_message",
        height=160,
        placeholder="Paste your message here..."
    )

    
    if st.button("Analyze Message", width="stretch"):

        if not message.strip():
            st.warning("Please enter a message.")

        else:
            try:
                # 1. Three-class machine-learning prediction (V4)
                prediction = str(model.predict([message])[0])
                probabilities = model.predict_proba([message])[0]
                class_scores = {
                    str(class_name): float(score)
                    for class_name, score in zip(model.classes_, probabilities)
                }

                required_classes = {"safe", "spam", "scam"}
                if not required_classes.issubset(class_scores):
                    raise ValueError(
                        "V4 model must contain safe, spam and scam classes. "
                        f"Found: {list(class_scores)}"
                    )

                spam_score = class_scores["spam"]
                scam_score = class_scores["scam"]
                unsafe_score = spam_score + scam_score

                # 2. Independent keyword-based analysis
                categories = detect_category(message)
                warnings = detect_warnings(message)

                has_warning_signs = (
                    warnings != [
                        "No warning phrases detected by the keyword rules."
                    ]
                )

                # 3. Model-based screening indicator.
                # These bands are project heuristics, not calibrated probabilities.
                if unsafe_score >= 0.75:
                    risk = "High"
                elif unsafe_score >= 0.45:
                    risk = "Medium"
                else:
                    risk = "Low"

                # 4. Display machine learning result
                st.divider()
                st.subheader("1. Machine Learning Analysis")

                st.metric("ML Prediction", prediction.upper())

                score_col1, score_col2, score_col3, score_col4 = st.columns(4)
                score_col1.metric("Safe Score", f"{class_scores['safe'] * 100:.2f}%")
                score_col2.metric("Spam Score", f"{spam_score * 100:.2f}%")
                score_col3.metric("Scam Score", f"{scam_score * 100:.2f}%")
                score_col4.metric("Combined Unsafe Score", f"{unsafe_score * 100:.2f}%")

                st.metric("Model Risk Indicator", risk)
                st.progress(min(max(unsafe_score, 0.0), 1.0))

                st.caption(
                    "Scores are model outputs, not verified fraud probabilities. "
                    "The combined unsafe score is the sum of the Spam and Scam "
                    "class scores; risk bands are heuristic screening indicators."
                )

                if prediction == "scam":
                    st.error(
                        "The model classified this message as scam-like. "
                        "Verify the sender independently and do not follow unexpected requests."
                    )
                elif prediction == "spam":
                    st.warning(
                        "The model classified this message as spam-like. "
                        "Treat unsolicited promotional messages cautiously."
                    )
                else:
                    st.success(
                        "The model classified this message as likely safe. "
                        "This does not guarantee that it is genuine."
                    )

                # 5. Display possible message categories
                st.divider()
                st.subheader("2. Possible Message Categories")

                for category in categories:
                    st.write(f"• {category}")

                # 6. Display independent warning signs
                st.divider()
                st.subheader("3. Independent Warning Signs")

                if has_warning_signs:
                    st.warning(
                        "One or more warning patterns were found. "
                        "Review this message carefully."
                    )

                    for warning in warnings:
                        st.write(f"⚠️ {warning}")

                else:
                    st.info(
                        "No warning phrases were detected by the "
                        "keyword rules. This does not prove the message is safe."
                    )

                # 7. Combined assessment
                st.divider()
                st.subheader("4. Overall Assessment")

                if prediction == "scam" and has_warning_signs:
                    st.error(
                        "High attention recommended: the model classified "
                        "this message as scam-like and the keyword rules "
                        "also found warning patterns."
                    )
                elif prediction == "scam":
                    st.error(
                        "The model classified this message as scam-like. "
                        "Review it carefully before taking any action."
                    )
                elif prediction == "spam" and has_warning_signs:
                    st.error(
                        "The model classified this message as spam-like "
                        "and independent warning patterns were also found."
                    )
                elif prediction == "spam":
                    st.warning(
                        "The machine-learning model flagged this message "
                        "as spam-like. Review it before taking action."
                    )
                elif has_warning_signs:
                    st.warning(
                        "Manual review recommended: the model classified "
                        "this message as likely safe, but warning patterns "
                        "were detected independently."
                    )
                else:
                    st.info(
                        "The model classified this message as likely safe "
                        "and the keyword rules found no warning phrases. "
                        "Still verify the sender independently."
                    )

                # 8. Safety recommendation
                st.divider()
                st.subheader("5. Safety Recommendation")

                st.write(
                    "Do not click unexpected links or share OTPs, "
                    "passwords, PINs, or banking information in response "
                    "to an unsolicited message. Verify important requests "
                    "through the organisation's official website or app."
                )

                # 9. Save history using the existing database structure
                record = {
                    "Message": message[:100],
                    "Prediction": prediction,
                    "Risk": risk,
                    "Spam Score": round(spam_score * 100, 2)
                }

                save_analysis(record)
                st.session_state.history = load_history()

                st.caption(
                    "Categories and warning signs are based on keyword "
                    "rules. They are indicators, not independently verified facts."
                )

            except Exception as error:
                st.error(f"Analysis failed: {error}")

# -----------------------------
# ANALYSIS HISTORY
# -----------------------------
elif page == "Analysis History":

    st.title("📊 Analysis History")
    st.write("View your message analysis records and project statistics.")

    st.session_state.history = load_history()

    if st.session_state.history:
        history_df = pd.DataFrame(st.session_state.history)

        total = len(history_df)
        spam_count = int((history_df["Prediction"] == "spam").sum())
        scam_count = int((history_df["Prediction"] == "scam").sum())
        safe_count = int((history_df["Prediction"] == "safe").sum())

        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Total Messages", total)
        col2.metric("Safe Messages", safe_count)
        col3.metric("Spam Messages", spam_count)
        col4.metric("Scam Messages", scam_count)

        st.divider()

        st.subheader("📈 Message Classification")
        prediction_counts = (
            history_df["Prediction"]
            .value_counts()
            .rename_axis("Prediction")
            .reset_index(name="Count")
        )
        st.bar_chart(
            prediction_counts,
            x="Prediction",
            y="Count",
            color="#22C55E",
            height=300,
            alt="Message classification counts"
        )

        st.subheader("⚠️ Risk Distribution")
        risk_counts = (
            history_df["Risk"]
            .value_counts()
            .rename_axis("Risk")
            .reset_index(name="Count")
        )
        st.bar_chart(
            risk_counts,
            x="Risk",
            y="Count",
            alt="Risk distribution"
        )

        st.divider()
        st.subheader("📋 All Analysis Records")
        st.dataframe(
            history_df,
            hide_index=True,
            alt="Saved message analysis records"
        )

        csv_data = history_df.to_csv(index=False).encode("utf-8")
        st.download_button(
            label="⬇️ Download Analysis Report (CSV)",
            data=csv_data,
            file_name="scamsathi_analysis_report.csv",
            mime="text/csv",
            width="stretch"
        )

        if st.button("🗑️ Clear History", width="stretch"):
            clear_database_history()
            st.session_state.history = load_history()
            st.rerun()
    else:
        st.info("No messages analyzed yet.")

# -----------------------------
# ABOUT PROJECT
# -----------------------------
elif page == "About Project":

    st.title("About ScamSathi")

    st.write("""
    ScamSathi is an educational AI/ML application
    that screens text messages for patterns associated
    with safe, spam and scam communication.

    It uses machine learning and keyword-based rules
    to identify potentially suspicious messages.

    The application is designed for educational purposes
    and does not guarantee fraud detection.
    """)
 