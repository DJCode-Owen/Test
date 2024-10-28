import PyPDF2
import re
import streamlit as st
import pandas as pd
import hashlib
import json
import os
import io
from streamlit import session_state

# Simple user database file
USER_DATABASE_FILE = 'user_database.json'
PROPERTY_DATABASE_FILE = 'property_database.json'
APPLICATION_DATABASE_FILE = 'application_database.json'

# Load user database
if os.path.exists(USER_DATABASE_FILE):
    with open(USER_DATABASE_FILE, 'r') as f:
        user_database = json.load(f)
else:
    user_database = {
        'admin': {'password': hashlib.sha256('asdf'.encode()).hexdigest(), 'role': 'admin'}
    }

# Load property database
if os.path.exists(PROPERTY_DATABASE_FILE):
    with open(PROPERTY_DATABASE_FILE, 'r') as f:
        property_database = json.load(f)
else:
    property_database = []

# Load application database
if os.path.exists(APPLICATION_DATABASE_FILE):
    with open(APPLICATION_DATABASE_FILE, 'r') as f:
        application_database = json.load(f)
else:
    application_database = []

# Save user database
def save_user_database():
    with open(USER_DATABASE_FILE, 'w') as f:
        json.dump(user_database, f)

# Save property database
def save_property_database():
    with open(PROPERTY_DATABASE_FILE, 'w') as f:
        json.dump(property_database, f)

# Save application database
def save_application_database():
    with open(APPLICATION_DATABASE_FILE, 'w') as f:
        json.dump(application_database, f)

# Registration function
def register_user(username, password, role):
    if username in user_database:
        return False, "Username already exists"
    user_database[username] = {'password': hashlib.sha256(password.encode()).hexdigest(), 'role': role}
    save_user_database()
    return True, "User registered successfully"

# Authentication function
def authenticate_user(username, password):
    if username in user_database:
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        return user_database[username]['password'] == hashed_password
    return False

# Function to extract values from PDFs
def extract_values_from_pdfs(files, keywords):
    # List to store extracted values for each file
    extracted_values_list = []
    
    # Loop through each uploaded file
    for file in files:
        file_values = {keyword: None for keyword in keywords}
        reader = PyPDF2.PdfReader(file)
        
        # Loop through each page in the file
        for page_num in range(len(reader.pages)):
            page = reader.pages[page_num]
            text = page.extract_text()
            
            # Extract values based on keywords
            if "vorname" in keywords or "nachname" in keywords:
                # Extract full name using a general name pattern
                name_pattern = r'\b(Name|Vorname|Nachname|Full Name|Applicant Name)\s*:\s*(.*?)\s*\n'
                match = re.search(name_pattern, text, re.IGNORECASE)
                if match:
                    full_name = match.group(2).strip()
                    name_parts = full_name.split()
                    if "vorname" in keywords and len(name_parts) > 0:
                        file_values["vorname"] = name_parts[0]
                    if "nachname" in keywords and len(name_parts) > 1:
                        file_values["nachname"] = " ".join(name_parts[1:])
                else:
                    # Try to find a full name without explicit labels
                    generic_name_pattern = r'\b([A-Z][a-z]+)\s+([A-Z][a-z]+)\b'
                    match = re.search(generic_name_pattern, text)
                    if match:
                        file_values["vorname"] = match.group(1)
                        file_values["nachname"] = match.group(2)
            
            for keyword in keywords:
                if keyword.lower() == "telefon" and file_values[keyword] is None:
                    # Extract phone numbers based on a general phone number pattern
                    phone_pattern = r'\b\+?\d{1,4}?[\s.-]?(?:\(\d{1,3}\))?[\s.-]?\d{1,4}[\s.-]?\d{1,4}[\s.-]?\d{1,9}\b'
                    matches = re.findall(phone_pattern, text)
                    if matches:
                        file_values[keyword] = matches[0]
                elif keyword.lower() == "e-mail" and file_values[keyword] is None:
                    # Extract email addresses based on a general email pattern
                    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
                    matches = re.findall(email_pattern, text)
                    if matches:
                        file_values[keyword] = matches[0]
                elif file_values[keyword] is None and keyword.lower() not in ["vorname", "nachname"]:
                    pattern = rf'{keyword}\s*:\s*(.*?)\s*\n'
                    match = re.search(pattern, text, re.IGNORECASE)
                    if match:
                        file_values[keyword] = match.group(1)
        
        extracted_values_list.append(file_values)
    
    return extracted_values_list

# Streamlit app
st.title("Property Management Portal")

# Startpage options
auth_action = st.sidebar.selectbox("Choose action", ["Login", "Register"])

# Registration and login
if auth_action == "Register":
    st.sidebar.subheader("Register")
    new_username = st.sidebar.text_input("Username", key="register_username")
    new_password = st.sidebar.text_input("Password", type="password", key="register_password")
    role = st.sidebar.selectbox("Role", ["Interessent", "Verwalter"], key="register_role")
    register_button = st.sidebar.button("Register", key="register_button")

    if register_button:
        success, message = register_user(new_username, new_password, role)
        st.sidebar.write(message)

elif auth_action == "Login":
    st.sidebar.subheader("Login")
    username = st.sidebar.text_input("Username", key="login_username")
    password = st.sidebar.text_input("Password", type="password", key="login_password")
    login_button = st.sidebar.button("Login", key="login_button")

    if login_button:
        if authenticate_user(username, password):
            session_state["authenticated"] = True
            session_state["username"] = username
            session_state["role"] = user_database[username]["role"]
            st.sidebar.write(f'Welcome *{username}* ({session_state["role"]})')
        else:
            st.sidebar.error("Username/password is incorrect")

# Display portal if logged in
if session_state.get("authenticated", False):
    if session_state.get("role") == "Interessent":
        st.subheader("Available Properties")
        # Display available properties from the property database
        for idx, property in enumerate(property_database):
            st.markdown(f"### {property['title']}")
            st.markdown(f"{property['description']}")
            with st.form(key=f"application_form_{idx}"):
                first_name = st.text_input("Vorname", key=f"first_name_{idx}")
                last_name = st.text_input("Nachname", key=f"last_name_{idx}")
                uploaded_application = st.file_uploader("Upload your application as PDF", type=["pdf"], key=f"upload_{idx}")
                submit_button = st.form_submit_button(label="Senden")

                if submit_button and first_name and last_name and uploaded_application:
                    application = {
                        "property_title": property['title'],
                        "first_name": first_name,
                        "last_name": last_name,
                        "pdf_file": uploaded_application.getvalue().decode('latin1')
                    }
                    application_database.append(application)
                    save_application_database()
                    st.success("Application submitted successfully!")
    elif session_state.get("role") == "Verwalter":
        st.subheader("Inserate")
        tab1, tab2, tab3 = st.tabs(["Bestand", "Hochladen", "PDF Scanner"])

        with tab1:
            st.subheader("Bestehende Inserate")
            for property in property_database:
                st.markdown("---")
                st.markdown(f"### {property['title']}")
                st.markdown(f"{property['description'] if property['description'] else 'Keine Beschreibung verfügbar'}")
                st.markdown("**Bewerbungen:**")
                for idx, application in enumerate(application_database):
                    if application['property_title'] == property['title']:
                        st.markdown(f"- {application['first_name']} {application['last_name']}")
                        

        with tab2:
            st.subheader("Neues Inserat hochladen")
            title = st.text_input("Titel der Immobilie")
            description = st.text_area("Beschreibung der Immobilie")
            upload_button = st.button("Inserat hochladen")

            if upload_button and title and description:
                new_property = {"title": title, "description": description}
                property_database.append(new_property)
                save_property_database()
                st.success("Inserat erfolgreich hochgeladen!")

        with tab3:
            st.subheader("Uploaded Applications")
            # File uploader for multiple applications
            uploaded_files = st.file_uploader("Upload application PDFs", type=["pdf"], accept_multiple_files=True)

            # Predefined keyword buttons
            st.subheader("Select keywords to extract")
            keyword_buttons = {
                "Vorname": st.checkbox("Vorname"),
                "Nachname": st.checkbox("Nachname"),
                "Einkommen": st.checkbox("Einkommen"),
                "E-Mail": st.checkbox("E-Mail"),
                "Telefon": st.checkbox("Telefon")
            }

            # Collect selected keywords
            selected_keywords = [key for key, value in keyword_buttons.items() if value]

            # Input for additional keywords
            keywords_input = st.text_input("Enter additional keywords to extract (comma separated)")

            if keywords_input:
                additional_keywords = [keyword.strip() for keyword in keywords_input.split(",")]
                selected_keywords.extend(additional_keywords)

            if uploaded_files and selected_keywords:
                # Extract values from the uploaded PDFs
                extracted_values_list = extract_values_from_pdfs(uploaded_files, selected_keywords)
                
                # Create a DataFrame from the list of dictionaries
                df = pd.DataFrame(extracted_values_list)
                
                # Drop columns that have all empty values
                df = df.dropna(how='all', axis=1)
                
                # Display the DataFrame with Streamlit's DataFrame component, enabling sorting
                st.subheader("Extracted Values")
                st.dataframe(df)
                
                if not df.empty:
                    # Provide a download button for the DataFrame as an Excel file
                    buffer = io.BytesIO()
                    with pd.ExcelWriter(buffer, engine='openpyxl') as writer:
                        df.to_excel(writer, index=False)
                    st.download_button(
                        label="Download data as Excel",
                        data=buffer,
                        file_name='extracted_values.xlsx',
                        mime='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
                    )
                else:
                    st.write("No matching values found.")

    elif session_state.get("role") == "admin":
        st.subheader("Admin Dashboard")
        st.write("List of all users:")
        for user in list(user_database.keys()):
            if user != 'admin':
                st.write(f"- {user} ({user_database[user]['role']})")
                if st.button(f"Delete {user}", key=f"delete_{user}"):
                    del user_database[user]
                    save_user_database()
                    st.success(f"User {user} deleted successfully!")
