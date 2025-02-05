import streamlit as st
import sqlite3
import hashlib
import os
import jwt as pyjwt
from datetime import datetime, timedelta
from PIL import Image
import google.generativeai as genai
from dotenv import load_dotenv
from gtts import gTTS
import base64

# Load environment variables
load_dotenv()

# Configure Gemini API
genai.configure(api_key=os.getenv("GOOGLE_API_KEY"))

# JWT Secret Key (store this securely in environment variables)
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "your-secret-key")
JWT_ALGORITHM = "HS256"

# Database setup for user authentication
def create_user_table():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (username TEXT PRIMARY KEY, 
                  password TEXT, 
                  email TEXT UNIQUE)''')
    conn.commit()
    conn.close()

# Hash password for secure storage
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# User registration
def register_user(username, password, email):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    
    try:
        hashed_password = hash_password(password)
        c.execute("INSERT INTO users (username, password, email) VALUES (?, ?, ?)", 
                  (username, hashed_password, email))
        conn.commit()
        return True
    except sqlite3.IntegrityError as e:
        if "UNIQUE constraint failed: users.username" in str(e):
            st.error("Username already exists. Please choose a different username.")
        elif "UNIQUE constraint failed: users.email" in str(e):
            st.error("Email already exists. Please use a different email address.")
        return False
    finally:
        conn.close()

# User login verification
def verify_login(username, password):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    
    hashed_password = hash_password(password)
    c.execute("SELECT * FROM users WHERE username = ? AND password = ?", 
              (username, hashed_password))
    
    user = c.fetchone()
    conn.close()
    
    return user is not None

# Generate JWT token
def generate_jwt_token(username):
    payload = {
        "username": username,
        "exp": datetime.utcnow() + timedelta(hours=1)  # Token expires in 1 hour
    }
    token = pyjwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    return token

# Verify JWT token
def verify_jwt_token(token):
    try:
        payload = pyjwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        print(f"Verified JWT Token: {token}")  # Print token to terminal
        return payload["username"]
    except pyjwt.ExpiredSignatureError:
        st.error("Token has expired. Please log in again.")
        return None
    except pyjwt.InvalidTokenError:
        st.error("Invalid token. Please log in again.")
        return None

# Admin user creation
def create_admin_user():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    
    c.execute('''CREATE TABLE IF NOT EXISTS admins
                 (username TEXT PRIMARY KEY, 
                  password TEXT)''')
    
    admin_username = 'admin'
    admin_password = hash_password('adminpassword')
    
    try:
        c.execute("INSERT OR IGNORE INTO admins (username, password) VALUES (?, ?)", 
                  (admin_username, admin_password))
        conn.commit()
    except sqlite3.IntegrityError:
        pass
    finally:
        conn.close()

# Verify admin login
def verify_admin_login(username, password):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    
    hashed_password = hash_password(password)
    c.execute("SELECT * FROM admins WHERE username = ? AND password = ?", 
              (username, hashed_password))
    
    user = c.fetchone()
    conn.close()
    
    return user is not None

# Get all users
def get_all_users():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    
    c.execute("SELECT username, email FROM users")
    users = c.fetchall()
    conn.close()
    
    return users

# Delete user
def delete_user(username):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    
    try:
        c.execute("DELETE FROM users WHERE username = ?", (username,))
        conn.commit()
        return c.rowcount > 0
    except sqlite3.Error:
        return False
    finally:
        conn.close()

# Admin dashboard
def admin_dashboard():
    st.title("Admin Dashboard")
    
    # Fetch all users
    users = get_all_users()
    
    # Display users in a table
    st.subheader("Registered Users")
    if users:
        user_df = {
            "Username": [user[0] for user in users],
            "Email": [user[1] for user in users]
        }
        st.dataframe(user_df)
        
        # User deletion
        delete_username = st.text_input("Enter username to delete")
        if st.button("Delete User"):
            if delete_user(delete_username):
                st.success(f"User {delete_username} deleted successfully")
                st.rerun()
            else:
                st.error("Failed to delete user")
    else:
        st.write("No users registered")

# Add this function to validate the image content
def validate_image_content(image):
    """
    Validate if the uploaded image is of food or vegetables using the Gemini API.
    """
    model = genai.GenerativeModel("gemini-1.5-flash")
    prompt = "Is this image of food or vegetables? Respond with 'Yes' or 'No'."
    
    # Ensure the image is in the correct format
    if isinstance(image, list):
        image = image[0]  # Take the first element if it's a list
    
    # Generate the response
    response = model.generate_content([prompt, image])
    return response.text.strip().lower() == "yes"

# Function to translate text using Gemini API
def translate_text(text, target_language):
    """
    Translate text into the target language using the Gemini API.
    """
    model = genai.GenerativeModel("gemini-1.5-flash")
    prompt = f"Translate the following text into {target_language}: {text}"
    response = model.generate_content(prompt)
    return response.text

# Function to convert text to speech and play it
LANGUAGE_MAPPING = {
    "English": "en",
    "Telugu": "te",
    "Hindi": "hi",
    "German": "de"
}

def text_to_speech(text, language='en'):
    """
    Convert text to speech and play it in the Streamlit app.
    """
    try:
        tts = gTTS(text=text, lang=language, slow=False)
        tts.save("response.mp3")
        
        # Play the audio file
        audio_file = open("response.mp3", "rb")
        audio_bytes = audio_file.read()
        st.audio(audio_bytes, format="audio/mp3")
    except ValueError as e:
        st.error(f"Error in text-to-speech conversion: {e}")

# Main application function
def main():
    st.header("Your Image to Recipe")
    
    language_options = ["English", "Telugu", "Hindi", "German"]
    selected_language = st.selectbox("Select Language:", language_options)
    
    # Get the ISO 639-1 language code for the selected language
    language_code = LANGUAGE_MAPPING.get(selected_language, "en")  # Default to English if not found
    
    if selected_language == "English":
        input_prompt1 = """
        Embark on a culinary exploration as you uncover the secrets of the delectable dish captured in the uploaded image:
        1. Discover key details about the dish, including its name and culinary essence.
        2. Explore the fascinating origins of the dish, unraveling its cultural and historical significance.
        3. Dive into the rich tapestry of ingredients, presented pointwise, that contribute to the dish's exquisite flavor profile.
        """
        
        input_prompt2 = """
        As the culinary maestro guiding eager chefs, lay out the meticulous steps for crafting the featured dish:
        1. Start with selecting the finest ingredients, emphasizing quality and freshness.
        2. Detail the process of washing, peeling, and chopping each ingredient with precision.
        3. Unveil the culinary artistry behind the cooking process, step by step.
        4. Share expert tips and techniques to elevate the dish from ordinary to extraordinary.
        """
        
        input_prompt3 = """
        In your role as a nutritional advisor, present a comprehensive overview of the dish's nutritional value:
        1. Display a table showcasing nutritional values in descending order, covering calories, protein, fat, and carbohydrates.
        2. Create a second table illustrating the nutritional contribution of each ingredient, unraveling the dietary secrets within.
        """
        
        input_prompt4 = """
        Act as a dietitian and nutritionist:
        1. Your task is to provide 2 vegetarian dish alternatives to the dish uploaded in the image which have the same nutritional value.
        2. Your task is to provide 2 Non-vegetarian dish alternatives to the dish uploaded in the image which have the same nutritional value.
        """
    else:
        # Translate prompts for other languages
        input_prompt1 = translate_text("""
        Embark on a culinary exploration as you uncover the secrets of the delectable dish captured in the uploaded image:
        1. Discover key details about the dish, including its name and culinary essence.
        2. Explore the fascinating origins of the dish, unraveling its cultural and historical significance.
        3. Dive into the rich tapestry of ingredients, presented pointwise, that contribute to the dish's exquisite flavor profile.
        """, selected_language)
        
        input_prompt2 = translate_text("""
        As the culinary maestro guiding eager chefs, lay out the meticulous steps for crafting the featured dish:
        1. Start with selecting the finest ingredients, emphasizing quality and freshness.
        2. Detail the process of washing, peeling, and chopping each ingredient with precision.
        3. Unveil the culinary artistry behind the cooking process, step by step.
        4. Share expert tips and techniques to elevate the dish from ordinary to extraordinary.
        """, selected_language)
        
        input_prompt3 = translate_text("""
        In your role as a nutritional advisor, present a comprehensive overview of the dish's nutritional value:
        1. Display a table showcasing nutritional values in descending order, covering calories, protein, fat, and carbohydrates.
        2. Create a second table illustrating the nutritional contribution of each ingredient, unraveling the dietary secrets within.
        """, selected_language)
        
        input_prompt4 = translate_text("""
        Act as a dietitian and nutritionist:
        1. Your task is to provide 2 vegetarian dish alternatives to the dish uploaded in the image which have the same nutritional value.
        2. Your task is to provide 2 Non-vegetarian dish alternatives to the dish uploaded in the image which have the same nutritional value.
        """, selected_language)
    
    input_text = st.text_input("Input Prompt: ", key="input")
    
    # Option to upload or capture image
    option = st.radio("Choose an option:", ["Upload Image", "Capture Image from Camera"])
    
    image = ""
    
    if option == "Upload Image":
        uploaded_file = st.file_uploader("Choose an image ...", type=["jpg", "jpeg", "png"])
        if uploaded_file is not None:
            image = Image.open(uploaded_file)
            st.image(image, caption="Uploaded Image.", use_column_width=True)
            
            # Validate the image content
            image_parts = input_image_setup(uploaded_file)
            if not validate_image_content(image_parts):
                st.error("🚫 The uploaded image is not recognized as food or vegetables. Please upload a valid image.")
                st.session_state['uploaded_file'] = None  # Remove the image from session state
                st.rerun()  # Rerun the app to clear the invalid image
            else:
                st.session_state['uploaded_file'] = uploaded_file  # Store the valid image in session state
                st.success("✅ The uploaded image is valid! You can now proceed.")
    else:
        captured_image = st.camera_input("Capture an image")
        if captured_image is not None:
            image = Image.open(captured_image)
            st.image(image, caption="Captured Image.", use_column_width=True)
            
            # Validate the image content
            image_parts = input_image_setup(captured_image)
            if not validate_image_content(image_parts):
                st.error("🚫 The captured image is not recognized as food or vegetables. Please capture a valid image.")
                st.session_state['captured_image'] = None  # Remove the image from session state
                st.rerun()  # Rerun the app to clear the invalid image
            else:
                st.session_state['captured_image'] = captured_image  # Store the valid image in session state
                st.success("✅ The captured image is valid! You can now proceed.")
    
    col1, col2 = st.columns(2)
    
    submit1 = col1.button("Get Dish Name and Ingredients")
    submit2 = col1.button("How to Cook")
    submit3 = col2.button("Nutritional Value for 1 Person")
    submit4 = col2.button("Alternative Dishes with Similar Nutritional Values")
    
    if submit1:
        if ('uploaded_file' in st.session_state and st.session_state['uploaded_file'] is not None) or ('captured_image' in st.session_state and st.session_state['captured_image'] is not None):
            if 'uploaded_file' in st.session_state and st.session_state['uploaded_file'] is not None:
                pdf_content = input_image_setup(st.session_state['uploaded_file'])
            else:
                pdf_content = input_image_setup(st.session_state['captured_image'])
            response = get_gemini_response(input_prompt1, pdf_content, input_text)
            translated_response = translate_text(response, selected_language)
            st.subheader("The Response is")
            st.write(translated_response)
            text_to_speech(translated_response, language=language_code)
        else:
            st.write("Please upload or capture the dish image.")

    if submit2:
        if ('uploaded_file' in st.session_state and st.session_state['uploaded_file'] is not None) or ('captured_image' in st.session_state and st.session_state['captured_image'] is not None):
            if 'uploaded_file' in st.session_state and st.session_state['uploaded_file'] is not None:
                pdf_content = input_image_setup(st.session_state['uploaded_file'])
            else:
                pdf_content = input_image_setup(st.session_state['captured_image'])
            response = get_gemini_response(input_prompt2, pdf_content, input_text)
            translated_response = translate_text(response, selected_language)
            st.subheader("The Response is")
            st.write(translated_response)
            text_to_speech(translated_response, language=language_code)
        else:
            st.write("Please upload or capture the dish image.")

    if submit3:
        if ('uploaded_file' in st.session_state and st.session_state['uploaded_file'] is not None) or ('captured_image' in st.session_state and st.session_state['captured_image'] is not None):
            if 'uploaded_file' in st.session_state and st.session_state['uploaded_file'] is not None:
                pdf_content = input_image_setup(st.session_state['uploaded_file'])
            else:
                pdf_content = input_image_setup(st.session_state['captured_image'])
            response = get_gemini_response(input_prompt3, pdf_content, input_text)
            translated_response = translate_text(response, selected_language)
            st.subheader("The Response is")
            st.write(translated_response)
            text_to_speech(translated_response, language=language_code)
        else:
            st.write("Please upload or capture the dish image.")

    if submit4:
        if ('uploaded_file' in st.session_state and st.session_state['uploaded_file'] is not None) or ('captured_image' in st.session_state and st.session_state['captured_image'] is not None):
            if 'uploaded_file' in st.session_state and st.session_state['uploaded_file'] is not None:
                pdf_content = input_image_setup(st.session_state['uploaded_file'])
            else:
                pdf_content = input_image_setup(st.session_state['captured_image'])
            response = get_gemini_response(input_prompt4, pdf_content, input_text)
            translated_response = translate_text(response, selected_language)
            st.subheader("The Response is")
            st.write(translated_response)
            text_to_speech(translated_response, language=language_code)
        else:
            st.write("Please upload or capture the dish image.")

# Existing functions from the original code
def get_gemini_response(input, image, prompt):
    model = genai.GenerativeModel("gemini-1.5-flash")
    response = model.generate_content([input, image[0], prompt])
    return response.text 

def input_image_setup(uploaded_file):
    if uploaded_file is not None:
        bytes_data = uploaded_file.getvalue()
        image_parts = [
            {
                "mime_type": uploaded_file.type,  
                "data": bytes_data
            }
        ]
        return image_parts
    else:
        raise FileNotFoundError("No file uploaded")

# Authentication and page routing
def auth_page():
    create_user_table()
    
    st.title("Image to Recipe App Authentication")
    
    # Determine if we're on login or signup page
    auth_type = st.radio("Choose Authentication Type:", ["Login", "Admin Login", "Sign Up"])
    
    if auth_type == "Login":
        st.subheader("Login")
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        
        if st.button("Login"):
            if verify_login(username, password):
                # Generate JWT token
                token = generate_jwt_token(username)
                print(f"Generated JWT Token: {token}")  # Print token to terminal
                st.session_state['authenticated'] = True
                st.session_state['username'] = username
                st.session_state['token'] = token
                st.session_state['is_admin'] = False
                st.rerun()
            else:
                st.error("Invalid username or password")
    
    elif auth_type == "Admin Login":
        st.subheader("Admin Login")
        username = st.text_input("Admin Username")
        password = st.text_input("Admin Password", type="password")
        
        if st.button("Admin Login"):
            if verify_admin_login(username, password):
                # Generate JWT token
                token = generate_jwt_token(username)
                print(f"Generated JWT Token: {token}")  # Print token to terminal
                st.session_state['authenticated'] = True
                st.session_state['username'] = username
                st.session_state['token'] = token
                st.session_state['is_admin'] = True
                st.rerun()
            else:
                st.error("Invalid admin credentials")
    
    else:
        st.subheader("Sign Up")
        new_username = st.text_input("Choose a Username")
        email = st.text_input("Email Address")
        new_password = st.text_input("Choose a Password", type="password")
        confirm_password = st.text_input("Confirm Password", type="password")
        
        if st.button("Sign Up"):
            if new_password != confirm_password:
                st.error("Passwords do not match")
            elif register_user(new_username, new_password, email):
                st.success("Account created successfully! Please login.")
            else:
                st.error("Username already exists")

def update_user_credentials(username, new_password=None, new_email=None):
    """
    Update user credentials in the database.
    
    Args:
        username (str): Current username
        new_password (str, optional): New password to update
        new_email (str, optional): New email to update
    
    Returns:
        bool: True if update successful, False otherwise
    """
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    
    try:
        # Prepare update query based on what's being updated
        updates = []
        params = []
        
        if new_password:
            hashed_password = hash_password(new_password)
            updates.append("password = ?")
            params.append(hashed_password)
        
        if new_email:
            # Check if the new email already exists
            c.execute("SELECT email FROM users WHERE email = ?", (new_email,))
            if c.fetchone():
                st.error("Email already exists. Please use a different email address.")
                return False
            updates.append("email = ?")
            params.append(new_email)
        
        # If no updates, return False
        if not updates:
            return False
        
        # Add username to params for WHERE clause
        params.append(username)
        
        # Construct and execute update query
        update_query = f"UPDATE users SET {', '.join(updates)} WHERE username = ?"
        c.execute(update_query, params)
        
        # Commit changes
        conn.commit()
        
        # Check if update was successful
        return c.rowcount > 0
    
    except sqlite3.Error as e:
        st.error(f"Database error: {e}")
        return False
    finally:
        conn.close()

def update_credentials_page():
    """
    Streamlit page for updating user credentials
    """
    st.title("Update User Credentials")
    
    # Ensure user is authenticated
    if not st.session_state.get('authenticated', False):
        st.error("Please log in first.")
        return
    
    # Get current username
    username = st.session_state.get('username')
    
    # Password update section
    st.subheader("Update Password")
    current_password = st.text_input("Current Password", type="password", key="current_pwd")
    new_password = st.text_input("New Password", type="password", key="new_pwd")
    confirm_password = st.text_input("Confirm New Password", type="password", key="confirm_pwd")
    
    # Email update section
    st.subheader("Update Email")
    new_email = st.text_input("New Email Address", key="new_email")
    
    # Update button
    if st.button("Update Credentials"):
        # Validate current login
        if not verify_login(username, current_password):
            st.error("Current password is incorrect.")
            return
        
        # Validate new password if changed
        if new_password:
            if new_password != confirm_password:
                st.error("New passwords do not match.")
                return
        
        # Perform updates
        password_updated = False
        email_updated = False
        
        if new_password:
            password_updated = update_user_credentials(username, new_password=new_password)
        
        if new_email:
            email_updated = update_user_credentials(username, new_email=new_email)
        
        # Provide feedback
        if password_updated and email_updated:
            st.success("Password and email updated successfully!")
        elif password_updated:
            st.success("Password updated successfully!")
        elif email_updated:
            st.success("Email updated successfully!")
        else:
            st.warning("No updates were made.")

# App function with JWT token verification
def app():
    st.set_page_config(page_title="Image to Recipe App", page_icon="🍲")
    
    create_user_table()
    create_admin_user()
    
    # Initialize session state for authentication
    if 'authenticated' not in st.session_state:
        st.session_state['authenticated'] = False
        st.session_state['username'] = None
        st.session_state['token'] = None
        st.session_state['is_admin'] = False
    
    # Verify JWT token if present
    if st.session_state.get('token'):
        username = verify_jwt_token(st.session_state['token'])
        if not username:
            st.session_state['authenticated'] = False
            st.session_state['username'] = None
            st.session_state['token'] = None
            st.rerun()
    
    # Authentication Page
    if not st.session_state['authenticated']:
        auth_page()
    else:
        # Sidebar navigation for authenticated users
        if st.session_state.get('is_admin', False):
            page = st.sidebar.radio("Admin Navigation", ["Admin Dashboard", "Update Credentials"])
        else:
            page = st.sidebar.radio("Navigation", ["Nutritionist App", "Update Credentials"])
        
        # Logout button
        if st.sidebar.button("Logout"):
            st.session_state['authenticated'] = False
            st.session_state['username'] = None
            st.session_state['token'] = None
            st.session_state['is_admin'] = False
            st.rerun()
        
        # Welcome message
        st.sidebar.write(f"Welcome, {st.session_state['username']}!")
        
        # Page Routing
        if st.session_state.get('is_admin', False) and page == "Admin Dashboard":
            admin_dashboard()
        elif page == "Nutritionist App":
            main()
        elif page == "Update Credentials":
            update_credentials_page()

if __name__ == "__main__":
    app()