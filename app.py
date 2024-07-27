#!/usr/bin/env python
# coding: utf-8

# In[ ]:


import os
import streamlit as st
from streamlit_extras.metric_cards import style_metric_cards # beautify metric card with css
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
import numpy as np
import bcrypt
from datetime import datetime
from matplotlib.patches import Patch
from matplotlib.lines import Line2D
import pymysql
from sqlalchemy import create_engine, text
import logging

# Configure logging
logging.basicConfig(filename='application.log', level=logging.INFO)

def connect_to_db():
    try:
        username = st.secrets["username"]
        password = st.secrets["password"]
        host = st.secrets["host"]
        database = st.secrets["database"]
        ssl_ca = 'DigiCertGlobalRootCA.crt.pem'

        connection_string = f'mysql+pymysql://{username}:{password}@{host}/{database}?ssl_ca={ssl_ca}'
        engine = create_engine(connection_string)
        with engine.connect() as connection:
            result = connection.execute(text("SELECT 1"))
            result.fetchone()

        return engine
    except Exception as err:
        st.sidebar.warning(f"Error: {err}")
        logging.error(f"Database connection error: {err}")
        return None
    
def fetch_risk_register_from_db():
    engine = connect_to_db()
    if engine:
        query = "SELECT * FROM risk_register"
        df = pd.read_sql(query, engine)
        engine.dispose()
        return df
    return pd.DataFrame(columns=fetch_columns_from_risk_data())

def fetch_columns_from_risk_data():
    engine = connect_to_db()
    if engine:
        with engine.connect() as connection:
            result = connection.execute(text("DESCRIBE risk_data"))
            columns = [row[0] for row in result.fetchall()]
        engine.dispose()
        return columns
    return []

def insert_uploaded_data_to_db(dataframe):
    engine = connect_to_db()
    if engine:
        with engine.connect() as connection:
            transaction = connection.begin()
            try:
                for _, row in dataframe.iterrows():
                    try:
                        date_last_updated = datetime.strptime(row['date_last_updated'], '%Y-%m-%d').date()
                    except ValueError:
                        date_last_updated = None
                    query = text("""
                        INSERT INTO risk_data (risk_description, risk_type, updated_by, date_last_updated, 
                                               cause_consequences, risk_owners, inherent_risk_probability, 
                                               inherent_risk_impact, inherent_risk_rating, control_owners, 
                                               residual_risk_probability, residual_risk_impact, 
                                               residual_risk_rating, controls) 
                        VALUES (:risk_description, :risk_type, :updated_by, :date_last_updated, :cause_consequences, 
                                :risk_owners, :inherent_risk_probability, :inherent_risk_impact, :inherent_risk_rating, 
                                :control_owners, :residual_risk_probability, :residual_risk_impact, :residual_risk_rating, 
                                :controls)
                    """)
                    connection.execute(query, row.to_dict())
                transaction.commit()
                st.sidebar.success("Data uploaded successfully!")
            except Exception as e:
                transaction.rollback()
                logging.error(f"Error inserting data: {e}")
                st.sidebar.error(f"Error inserting data: {e}")
        engine.dispose()

def insert_into_risk_data(data):
    engine = connect_to_db()
    if engine:
        with engine.connect() as connection:
            transaction = connection.begin()
            try:
                placeholders = ', '.join([':{}'.format(key) for key in data.keys()])
                columns = ', '.join([f"`{key}`" for key in data.keys()])
                query = text(f"INSERT INTO risk_data ({columns}) VALUES ({placeholders})")
                connection.execute(query, data)
                transaction.commit()
                logging.info(f"Inserted data: {data}")
            except Exception as e:
                transaction.rollback()
                st.write(f"Error during insertion to risk_data: {e}")
                logging.error(f"Error during insertion: {e}")
        engine.dispose()

def fetch_all_from_risk_data():
    engine = connect_to_db()
    if engine:
        query = "SELECT * FROM risk_data"
        data = pd.read_sql(query, engine)
        engine.dispose()
        return data
    return pd.DataFrame()

def delete_from_risk_data_by_risk_description(risk_description):
    if 'user_role' in st.session_state and st.session_state.user_role == 'admin':
        engine = connect_to_db()
        if engine:
            with engine.connect() as connection:
                transaction = connection.begin()
                try:
                    query = text("DELETE FROM risk_data WHERE TRIM(risk_description) = :risk_description")
                    result = connection.execute(query, {"risk_description": risk_description})
                    transaction.commit()
                    if result.rowcount > 0:
                        st.success(f"Risk '{risk_description}' deleted.")
                        logging.info(f"Deleted risk description: {risk_description}, Rows affected: {result.rowcount}")
                    else:
                        st.warning(f"No risk found with description '{risk_description}'.")
                except Exception as e:
                    transaction.rollback()
                    st.error(f"Error deleting risk: {e}")
                    logging.error(f"Error deleting risk {risk_description}: {e}")
            engine.dispose()
    else:
        st.error("You do not have permission to delete risks.")

def update_risk_data_by_risk_description(risk_description, data):
    if 'user_role' in st.session_state and st.session_state.user_role == 'admin':
        engine = connect_to_db()
        if engine:
            with engine.connect() as connection:
                transaction = connection.begin()
                try:
                    set_clause = ", ".join([f"{key} = :{key}" for key in data.keys()])
                    query = text(f"UPDATE risk_data SET {set_clause} WHERE risk_description = :risk_description")
                    data['risk_description'] = risk_description
                    result = connection.execute(query, data)
                    transaction.commit()
                    if result.rowcount > 0:
                        st.success("Risk updated successfully.")
                        logging.info(f"Updated risk data for {risk_description}: {data}")
                    else:
                        st.warning(f"No risk found with description '{risk_description}'.")
                except Exception as e:
                    transaction.rollback()
                    st.error(f"Error updating risk: {e}")
                    logging.error(f"Error updating risk {risk_description}: {e}")
            engine.dispose()
    else:
        st.error("You do not have permission to update risks.")


def get_risk_id_by_description(risk_description):
    engine = connect_to_db()
    if engine:
        with engine.connect() as connection:
            query = text("SELECT id FROM risk_data WHERE TRIM(risk_description) = :risk_description")
            result = connection.execute(query, {"risk_description": risk_description})
            risk_id = result.fetchone()
        engine.dispose()
        return risk_id[0] if risk_id else None
    
def fetch_risks_outside_appetite_from_risk_data(risk_appetite):
    engine = connect_to_db()
    if engine:
        with engine.connect() as connection:
            # Use a parameterized query for a list of values
            placeholders = ', '.join([f":rating_{i}" for i in range(len(risk_appetite))])
            query = text(f"SELECT * FROM risk_data WHERE residual_risk_rating NOT IN ({placeholders})")
            # Create a dictionary with unique parameter names for each rating
            params = {f"rating_{i}": rating for i, rating in enumerate(risk_appetite)}
            result = connection.execute(query, params)
            data = pd.DataFrame(result.fetchall(), columns=result.keys())
        engine.dispose()
        return data
    return pd.DataFrame()

def insert_risks_into_risk_register(data):
    engine = connect_to_db()
    if engine:
        with engine.connect() as connection:
            transaction = connection.begin()
            try:
                if isinstance(data, pd.DataFrame):
                    data_list = data.to_dict(orient='records')
                else:
                    data_list = [data]

                allowed_columns = ['risk_description', 'risk_type', 'updated_by', 'date_last_updated', 
                                   'cause_consequences', 'risk_owners', 'inherent_risk_probability', 
                                   'inherent_risk_impact', 'inherent_risk_rating', 'control_owners', 
                                   'residual_risk_probability', 'residual_risk_impact', 'residual_risk_rating', 
                                   'controls']
                
                for record in data_list:
                    record = {k: v for k, v in record.items() if k in allowed_columns}
                    
                    placeholders = ', '.join([f":{key}" for key in record.keys()])
                    columns = ', '.join(record.keys())
                    query = text(f"INSERT INTO risk_register ({columns}) VALUES ({placeholders})")
                    
                    logging.info(f"Executing query: {query} with parameters: {record}")
                    connection.execute(query, record)
                
                transaction.commit()
                logging.info(f"Inserted into risk_register: {data_list}")
            except Exception as e:
                transaction.rollback()
                logging.error(f"Error inserting into risk_register: {e}")
        engine.dispose()

def fetch_all_from_risk_register():
    engine = connect_to_db()
    if engine:
        query = "SELECT * FROM risk_register"
        data = pd.read_sql(query, engine)
        engine.dispose()
        return data
    return pd.DataFrame()

def update_risk_register_by_risk_description(risk_description, data):
    if 'user_role' in st.session_state and st.session_state.user_role == 'admin':
        engine = connect_to_db()
        if engine:
            with engine.connect() as connection:
                transaction = connection.begin()
                try:
                    set_clause = ", ".join([f"{key} = :{key}" for key in data.keys()])
                    query = text(f"UPDATE risk_register SET {set_clause} WHERE risk_description = :risk_description")
                    connection.execute(query, data)
                    transaction.commit()
                    st.success("Risk updated successfully.")
                    logging.info(f"Updated risk_register for {risk_description}: {data}")
                except Exception as e:
                    transaction.rollback()
                    st.error(f"Error updating risk register: {e}")
                    logging.error(f"Error updating risk register {risk_description}: {e}")
            engine.dispose()
    else:
        st.error("You do not have permission to update risks.")

def delete_from_risk_register_by_risk_description(risk_description):
    if 'user_role' in st.session_state and st.session_state.user_role == 'admin':
        engine = connect_to_db()
        if engine:
            with engine.connect() as connection:
                transaction = connection.begin()
                try:
                    query = text("DELETE FROM risk_register WHERE risk_description = :risk_description")
                    connection.execute(query, {"risk_description": risk_description})
                    transaction.commit()
                    st.success(f"Risk '{risk_description}' deleted.")
                    logging.info(f"Deleted risk_register description: {risk_description}")
                except Exception as e:
                    transaction.rollback()
                    st.error(f"Error deleting risk: {e}")
                    logging.error(f"Error deleting risk {risk_description}: {e}")
            engine.dispose()
    else:
        st.error("You do not have permission to delete risks.")
        
def register(username, password):
    engine = connect_to_db()
    if engine is None:
        logging.error("Failed to connect to the database.")
        return False
    
    try:
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        logging.debug(f"Hashed password for {username}: {hashed_password}")
    except Exception as e:
        logging.error(f"Password hashing failed for {username}: {e}")
        st.sidebar.warning(f"Password hashing error: {e}")
        return False

    try:
        with engine.connect() as connection:
            query = text("INSERT INTO credentials (username, password) VALUES (:username, :password)")
            result = connection.execute(query, {"username": username, "password": hashed_password.decode('utf-8')})
            connection.commit()  # Ensure the transaction is committed
            logging.info(f"Registered new user {username}, Rows affected: {result.rowcount}")
        return True
    except Exception as err:
        logging.error(f"Registration error for user {username}: {err}")
        st.sidebar.warning(f"Error: {err}")
        return False
    
# Initialize session state variables
if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False

if 'username' not in st.session_state:
    st.session_state.username = ""

if 'user_role' not in st.session_state:
    st.session_state.user_role = ""
    
# Initialize session state variables
if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False

if 'username' not in st.session_state:
    st.session_state.username = ""

if 'user_role' not in st.session_state:
    st.session_state.user_role = ""
    
def login(username, password):
    logging.info(f"Attempting login for username: {username}")
    engine = connect_to_db()
    if engine:
        try:
            with engine.connect() as connection:
                query = text("SELECT password, expiry_date, role FROM credentials WHERE username = :username")
                result = connection.execute(query, {"username": username})
                row = result.fetchone()

                if row:
                    stored_password, expiry_date, role = row
                    logging.info(f"Fetched credentials for {username}")

                    if stored_password:
                        if bcrypt.checkpw(password.encode('utf-8'), stored_password.encode('utf-8')):
                            logging.info(f"Password matched for {username}")

                            if expiry_date:
                                try:
                                    expiry_date = datetime.strptime(str(expiry_date), '%Y-%m-%d')
                                    if expiry_date < datetime.now():
                                        st.sidebar.error("Your account has expired. Please contact the administrator.")
                                        logging.info(f"Account expired for {username}")
                                        return False
                                except ValueError:
                                    st.sidebar.error("Invalid expiry date format. Please contact the administrator.")
                                    logging.error(f"Invalid expiry date format for {username}: {expiry_date}")
                                    return False

                            if not role:
                                st.sidebar.error("No role found for the user. Please contact the administrator.")
                                logging.error(f"No role found for {username}")
                                return False

                            # If login is successful
                            st.session_state.logged_in = True
                            st.session_state.username = username
                            st.session_state.user_role = role
                            logging.info(f"User {username} logged in successfully with role {role}.")
                            return True
                        else:
                            logging.info(f"Invalid credentials for {username}")
                            return False
                    else:
                        logging.error(f"Stored password is missing for {username}")
                        return False
                else:
                    logging.info(f"Username not found: {username}")
                    return False
        except Exception as e:
            logging.error(f"Login error: {e}")
        finally:
            engine.dispose()
    return False

def logout():
    """Logout the user and clear session state."""
    for key in list(st.session_state.keys()):
        del st.session_state[key]
    st.session_state.logged_in = False
    
def change_password(username, current_password, new_password):
    logging.info(f"Initiating password change for user: {username}")
    engine = connect_to_db()
    if engine:
        try:
            with engine.begin() as connection:  # Use a transaction
                # Verify the current password
                query = text("SELECT password FROM credentials WHERE username = :username")
                result = connection.execute(query, {"username": username})
                row = result.fetchone()
                
                if row:
                    stored_password = row[0]
                    logging.info(f"Stored password hash: {stored_password}")

                    # Check if the current password matches the stored password
                    if bcrypt.checkpw(current_password.encode('utf-8'), stored_password.encode('utf-8')):
                        logging.info("Current password verified successfully.")

                        # Hash the new password
                        new_hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
                        logging.info(f"New hashed password: {new_hashed_password}")

                        # Update with the new password
                        update_query = text("UPDATE credentials SET password = :new_password WHERE username = :username")
                        result = connection.execute(update_query, {"new_password": new_hashed_password, "username": username})
                        if result.rowcount == 1:
                            logging.info("Password updated in the database.")
                            return True
                        else:
                            logging.error("Password update failed, no rows affected.")
                            st.sidebar.error("Password update failed.")
                            return False
                    else:
                        logging.warning("Current password verification failed.")
                        st.sidebar.error("The current password you entered is incorrect.")
                        return False
                else:
                    logging.warning(f"User {username} not found in the database.")
                    st.sidebar.error("User not found.")
                    return False
        except Exception as e:
            logging.error(f"Error during password change: {e}")
            st.sidebar.error("An error occurred while changing the password.")
            return False
    else:
        logging.error("Failed to connect to the database.")
        st.sidebar.error("Could not connect to the database.")
        return False

def main():
    st.image("logo.png", width=200)
    st.markdown('### Enterprise Risk Management Application')
    
    if not st.session_state.logged_in:
        st.sidebar.header("Login")
        username = st.sidebar.text_input("Username", key="login_username")
        password = st.sidebar.text_input("Password", type="password", key="login_password")
        if st.sidebar.button("Login", key="login_button"):
            if login(username, password):
                st.sidebar.success(f"Logged in as: {st.session_state.username}")
                st.sidebar.info(f"Role: {st.session_state.user_role}")
            else:
                st.sidebar.error("Login failed. Please check your credentials.")
    else:
        st.sidebar.header(f"Welcome, {st.session_state.username}")
        st.sidebar.info(f"Role: {st.session_state.user_role}")
        if st.sidebar.button("Logout", key="logout_button"):
            logout()
            st.sidebar.success("Logged out successfully!")

        # Password change form in the sidebar
        st.sidebar.subheader("Change Password")
        current_password = st.sidebar.text_input("Current Password", type="password", key="current_password")
        new_password = st.sidebar.text_input("New Password", type="password", key="new_password")
        confirm_new_password = st.sidebar.text_input("Confirm New Password", type="password", key="confirm_new_password")
        if st.sidebar.button("Change Password"):
            if new_password == confirm_new_password:
                if change_password(st.session_state.username, current_password, new_password):
                    st.sidebar.success("Password changed successfully.")
                else:
                    st.sidebar.error("Current password is incorrect.")
            else:
                st.sidebar.error("New passwords do not match.")

    # Additional application logic goes here
    if st.session_state.logged_in:
        st.write(f"Welcome {st.session_state.username}! You are logged in as {st.session_state.user_role}.")
    else:
        st.write("Please log in to access the application.")
    
    if st.session_state.logged_in and st.session_state.user_role == 'admin':
        st.sidebar.subheader("Register New User")
        new_username = st.sidebar.text_input("New Username", key='reg_username')
        new_password = st.sidebar.text_input("New Password", type="password", key='reg_password')
        if st.sidebar.button("Register"):
            if register(new_username, new_password):
                st.sidebar.success("Registered successfully! The new user can now log in.")
            else:
                st.sidebar.error("Registration failed. The username might already be taken.")
    elif st.session_state.logged_in:
        st.sidebar.info("Only admin users can register new users.")

    if st.session_state.logged_in:
        # Main application content goes here
        def plot_risk_matrix():
            fig = plt.figure()
            plt.subplots_adjust(wspace=0, hspace=0)
            plt.xticks([0.5, 1.5, 2.5, 3.5, 4.5], ['Very Low', 'Low', 'Medium', 'High', 'Very High'])
            plt.yticks([0.5, 1.5, 2.5, 3.5, 4.5], ['Very Low', 'Low', 'Medium', 'High', 'Very High'])
            plt.xlim(0, 5)
            plt.ylim(0, 5)
            plt.xlabel('Impact')
            plt.ylabel('Probability')

            nrows = 5
            ncols = 5
            axes = [fig.add_subplot(nrows, ncols, r * ncols + c + 1) for r in range(0, nrows) for c in range(0, ncols)]

            for ax in axes:
                ax.set_xticks([])
                ax.set_yticks([])
                ax.set_xlim(0, 5)
                ax.set_ylim(0, 5)

            green = [10, 15, 16, 20, 21]
            yellow = [0, 5, 6, 11, 17, 22, 23]
            orange = [1, 2, 7, 12, 13, 18, 24]
            red = [3, 4, 8, 9, 14, 19]

            for _ in green:
                axes[_].set_facecolor('green')
            for _ in yellow:
                axes[_].set_facecolor('yellow')
            for _ in orange:
                axes[_].set_facecolor('orange')
            for _ in red:
                axes[_].set_facecolor('red')

            axes[10].text(0.1, 0.8, 'Sustainable')
            axes[15].text(0.1, 0.8, 'Sustainable')
            axes[20].text(0.1, 0.8, 'Sustainable')
            axes[16].text(0.1, 0.8, 'Sustainable')
            axes[21].text(0.1, 0.8, 'Sustainable')

            axes[0].text(0.1, 0.8, 'Moderate')
            axes[5].text(0.1, 0.8, 'Moderate')
            axes[6].text(0.1, 0.8, 'Moderate')
            axes[11].text(0.1, 0.8, 'Moderate')
            axes[17].text(0.1, 0.8, 'Moderate')
            axes[22].text(0.1, 0.8, 'Moderate')
            axes[23].text(0.1, 0.8, 'Moderate')

            axes[1].text(0.1, 0.8, 'Severe')
            axes[2].text(0.1, 0.8, 'Severe')
            axes[7].text(0.1, 0.8, 'Severe')
            axes[12].text(0.1, 0.8, 'Severe')
            axes[13].text(0.1, 0.8, 'Severe')
            axes[18].text(0.1, 0.8, 'Severe')
            axes[24].text(0.1, 0.8, 'Severe')

            axes[3].text(0.1, 0.8, 'Critical')
            axes[8].text(0.1, 0.8, 'Critical')
            axes[4].text(0.1, 0.8, 'Critical')
            axes[9].text(0.1, 0.8, 'Critical')
            axes[14].text(0.1, 0.8, 'Critical')
            axes[19].text(0.1, 0.8, 'Critical')

            st.pyplot(fig)

        risk_levels = {
            'Very Low': 1, 'Low': 2, 'Medium': 3, 'High': 4, 'Very High': 5
        }

        risk_rating_dict = {
            (1, 1): 'Sustainable', (1, 2): 'Sustainable', (1, 3): 'Moderate', (1, 4): 'Severe', (1, 5): 'Severe',
            (2, 1): 'Sustainable', (2, 2): 'Moderate', (2, 3): 'Severe', (2, 4): 'Severe', (2, 5): 'Critical',
            (3, 1): 'Moderate', (3, 2): 'Severe', (3, 3): 'Severe', (3, 4): 'Critical', (3, 5): 'Critical',
            (4, 1): 'Severe', (4, 2): 'Severe', (4, 3): 'Critical', (4, 4): 'Critical', (4, 5): 'Critical',
            (5, 1): 'Severe', (5, 2): 'Critical', (5, 3): 'Critical', (5, 4): 'Critical', (5, 5): 'Critical'
        }
        
        def calculate_risk_rating(probability, impact):
            risk_level_num = risk_levels.get(probability, None), risk_levels.get(impact, None)
            rating = risk_rating_dict.get(risk_level_num, 'Unknown')
            if rating == 'Low':
                rating = 'Medium'  # Correcting the erroneous 'Low' rating
            return rating


#         def calculate_risk_rating(probability, impact):
#             return risk_rating_dict[(risk_levels[probability], risk_levels[impact])]

        tab = st.sidebar.selectbox(
            'Choose a function',
            ('Main Application', 'Risks Overview', 'Risks Owners & Control Owners', 'Adjusted Risk Matrices', 'Delete Risk', 'Update Risk')
        )

        if 'risk_data' not in st.session_state:
#             st.session_state['risk_data'] = fetch_risk_register_from_db()
            st.session_state['risk_data'] = fetch_all_from_risk_data()
            if st.session_state['risk_data'].empty:
                st.session_state['risk_data'] = pd.DataFrame(columns=[
                    'risk_description', 'cause_consequences', 'risk_owners', 
                    'inherent_risk_probability', 'inherent_risk_impact', 'inherent_risk_rating',
                    'controls', 'control_owners', 
                    'residual_risk_probability', 'residual_risk_impact', 'residual_risk_rating'
                ])

        if 'risk_register' not in st.session_state:
            st.session_state['risk_register'] = fetch_risk_register_from_db()

        if 'risk_appetite' not in st.session_state:
            st.session_state['risk_appetite'] = ['Critical', 'Severe', 'Moderate', 'Sustainable']

        if 'risk_type' not in st.session_state:
            st.session_state['risk_type'] = ''

        if 'updated_by' not in st.session_state:
            st.session_state['updated_by'] = ''

        if 'date_last_updated' not in st.session_state:
            st.session_state['date_last_updated'] = pd.to_datetime('today')

        if tab == 'Main Application':
            if 'risk_data' not in st.session_state:
                st.session_state['risk_data'] = fetch_all_from_risk_data()

            st.subheader('Master Risk Matrix')
            plot_risk_matrix()
            
            st.sidebar.subheader('Upload Risk Data')
            uploaded_file = st.sidebar.file_uploader("Choose a CSV file", type="csv")
            if uploaded_file:
                if st.sidebar.button("Upload"):
                    data = pd.read_csv(uploaded_file)
                    required_columns = [
                        'risk_description', 'risk_type', 'updated_by', 'date_last_updated',
                        'cause_consequences', 'risk_owners', 'inherent_risk_probability', 
                        'inherent_risk_impact', 'inherent_risk_rating', 'control_owners',
                        'residual_risk_probability', 'residual_risk_impact', 'residual_risk_rating', 
                        'controls'
                    ]
                    if set(required_columns).issubset(data.columns):
                        insert_uploaded_data_to_db(data)
                        st.sidebar.success("Data uploaded successfully!")
                    else:
                        st.sidebar.error("The uploaded file does not have the required columns")
            
            st.subheader('Enter Risk Details')

            if 'risk_appetite' not in st.session_state:
                st.session_state['risk_appetite'] = ['Critical', 'Severe', 'Moderate', 'Sustainable']

            selected_appetite = st.multiselect(
                'Risk Appetite', 
                ['Critical', 'Severe', 'Moderate', 'Sustainable'], 
                default=st.session_state['risk_appetite']
            )
            st.session_state['risk_appetite'] = selected_appetite

            st.session_state['risk_type'] = st.selectbox('Risk Type', [
                'Strategic risk', 'Operational risks', 'Organizational risks', 
                'Reputation risks', 'Market risks', 'Compliance & Regulatory risks', 
                'Hazard risks', 'Financial risks' ,'Project risks'
            ])
            st.session_state['updated_by'] = st.text_input('Updated By')
            st.session_state['date_last_updated'] = st.date_input('Date Last Updated')
            risk_description = st.text_input('Risk Description', key='risk_description')
            cause_consequences = st.text_input('Cause & Consequences', key='cause_consequences')
            risk_owners = st.text_input('Risk Owner(s)', key='risk_owners')
            inherent_risk_probability = st.selectbox('Inherent Risk Probability', list(risk_levels.keys()), key='inherent_risk_probability')
            inherent_risk_impact = st.selectbox('Inherent Risk Impact', list(risk_levels.keys()), key='inherent_risk_impact')
            controls = st.text_input('Control(s)', key='controls')
            control_owners = st.text_input('Control Owner(s)', key='control_owners')
            residual_risk_probability = st.selectbox('Residual Risk Probability', list(risk_levels.keys()), key='residual_risk_probability')
            residual_risk_impact = st.selectbox('Residual Risk Impact', list(risk_levels.keys()), key='residual_risk_impact')

            if st.button('Enter Risk'):
                inherent_risk_rating = calculate_risk_rating(inherent_risk_probability, inherent_risk_impact)
                residual_risk_rating = calculate_risk_rating(residual_risk_probability, residual_risk_impact)

                new_risk = {
                    'risk_type': st.session_state['risk_type'],
                    'updated_by': st.session_state['updated_by'],
                    'date_last_updated': st.session_state['date_last_updated'],
                    'risk_description': risk_description,
                    'cause_consequences': cause_consequences,
                    'risk_owners': risk_owners, 
                    'inherent_risk_probability': inherent_risk_probability,
                    'inherent_risk_impact': inherent_risk_impact,
                    'inherent_risk_rating': inherent_risk_rating,
                    'controls': controls,
                    'control_owners': control_owners,
                    'residual_risk_probability': residual_risk_probability,
                    'residual_risk_impact': residual_risk_impact,
                    'residual_risk_rating': residual_risk_rating
                }
                
                try:
                    insert_into_risk_data(new_risk)
                    st.write("New risk data successfully entered")
                except Exception as e:
                    st.write(f"Error inserting into risk_data: {e}")
                
                st.session_state['risk_data'] = fetch_all_from_risk_data()
                risk_appetite_values = st.session_state['risk_appetite']
                st.session_state['risk_register'] = fetch_risks_outside_appetite_from_risk_data(risk_appetite_values)

                try:
                    insert_risks_into_risk_register(st.session_state['risk_register'])
                except Exception as e:
                    st.write(f"Error inserting into risk_register: {e}")

                risks_outside_appetite = fetch_risks_outside_appetite_from_risk_data(risk_appetite_values)

                if not risks_outside_appetite.empty:
                    try:
                        risk_data_dict = risks_outside_appetite.iloc[0].to_dict()
                        insert_risks_into_risk_register(risk_data_dict)
                    except Exception as e:
                        st.write(f"Error inserting into risk_register: {e}")

            st.subheader('Risk Filters')
            
            # Assuming fetch_all_from_risk_data() returns a DataFrame with a 'date_last_updated' column
            st.session_state['risk_data'] = fetch_all_from_risk_data()

            # Ensure 'date_last_updated' is in datetime format
            st.session_state['risk_data']['date_last_updated'] = pd.to_datetime(st.session_state['risk_data']['date_last_updated'])

            # Date filter section
            min_date = st.session_state['risk_data']['date_last_updated'].min().date()
            max_date = st.session_state['risk_data']['date_last_updated'].max().date()

            from_date = st.date_input('From', value=min_date, min_value=min_date, max_value=max_date)
            to_date = st.date_input('To', value=max_date, min_value=min_date, max_value=max_date)

            # Apply date filter to the data
            filtered_data = st.session_state['risk_data'][
                (st.session_state['risk_data']['date_last_updated'] >= pd.Timestamp(from_date)) &
                (st.session_state['risk_data']['date_last_updated'] <= pd.Timestamp(to_date))
            ]
            
            st.subheader('Risk Data')

            st.write(filtered_data)

            if not filtered_data.empty:
                csv = filtered_data.to_csv(index=False)
                current_datetime = datetime.now().strftime('%Y%m%d%H%M%S')
                st.download_button(
                    label="Download Risk Data",
                    data=csv,
                    file_name=f"risk_data_{current_datetime}.csv",
                    mime="text/csv",
                )
            else:
                st.write("No risk data available to download.")
            
            st.subheader('Risk Register')
            risk_appetite = st.session_state.get('risk_appetite', [])
            mask = (~st.session_state['risk_data']['inherent_risk_rating'].isin(risk_appetite)) & (~st.session_state['risk_data']['residual_risk_rating'].isin(risk_appetite))
            risk_register = st.session_state['risk_data'][mask]
            st.write(risk_register)

            if not risk_register.empty:
                csv_register = risk_register.to_csv(index=False)
                current_datetime = datetime.now().strftime('%Y%m%d%H%M%S')
                st.download_button(
                    label="Download Risk Register",
                    data=csv_register,
                    file_name=f"risk_register_{current_datetime}.csv",
                    mime="text/csv",
                )
            else:
                st.write("No risk register data available to download.")
                
        elif tab == 'Risks Overview':
            st.markdown("""
            <style>
                body .stMetric span:first-child {
                    font-size: 12px !important; 
                }
                body .stMetric span:last-child {
                    font-size: 16px !important;
                }
            </style>
            """, unsafe_allow_html=True)

            if 'risk_data' not in st.session_state:
                st.session_state['risk_data'] = fetch_all_from_risk_data()

            st.header('Risks Dashboard')
            
            st.subheader('Date Filters')
           
            risk_data = st.session_state['risk_data']

            # Ensure 'date_last_updated' is in datetime format
            risk_data['date_last_updated'] = pd.to_datetime(risk_data['date_last_updated'])

            # Date filter section
            min_date = risk_data['date_last_updated'].min()
            max_date = risk_data['date_last_updated'].max()

            from_date = st.date_input('From', value=min_date.date(), min_value=min_date.date(), max_value=max_date.date())
            to_date = st.date_input('To', value=max_date.date(), min_value=min_date.date(), max_value=max_date.date())

            # Apply date filter to the data
            filtered_data = risk_data[(risk_data['date_last_updated'] >= pd.Timestamp(from_date)) &
                                      (risk_data['date_last_updated'] <= pd.Timestamp(to_date))]
            
            st.subheader('Before Risk Appetite')

            risk_rating_counts = filtered_data['inherent_risk_rating'].value_counts()

            critical_count = risk_rating_counts.get('Critical', 0)
            severe_count = risk_rating_counts.get('Severe', 0)
            moderate_count = risk_rating_counts.get('Moderate', 0)
            sustainable_count = risk_rating_counts.get('Sustainable', 0)

            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("Critical Inherent Risks", critical_count)
            with col2:
                st.metric("Severe Inherent Risks", severe_count)
            with col3:
                st.metric("Moderate Inherent Risks", moderate_count)
            with col4:
                st.metric("Sustainable Inherent Risks", sustainable_count)

            style_metric_cards(border_left_color="#DBF227")

            residual_risk_rating_counts = filtered_data['residual_risk_rating'].value_counts()

            residual_critical_count = residual_risk_rating_counts.get('Critical', 0)
            residual_severe_count = residual_risk_rating_counts.get('Severe', 0)
            residual_moderate_count = residual_risk_rating_counts.get('Moderate', 0)
            residual_sustainable_count = residual_risk_rating_counts.get('Sustainable', 0)

            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("Critical Residual Risks", residual_critical_count)
            with col2:
                st.metric("Severe Residual Risks", residual_severe_count)
            with col3:
                st.metric("Moderate Residual Risks", residual_moderate_count)
            with col4:
                st.metric("Sustainable Residual Risks", residual_sustainable_count)

            style_metric_cards(border_left_color="#DBF227")

            risk_type_counts = filtered_data['risk_type'].value_counts()

            fig = plt.figure(figsize=(10, 6))
            bars = plt.bar(risk_type_counts.index, risk_type_counts.values, color='skyblue')
            plt.title("Risk Types Count")
            plt.ylabel("Count")
            plt.xticks(rotation=45)

            for bar in bars:
                yval = bar.get_height()
                plt.text(bar.get_x() + bar.get_width()/2, yval - 0.5, yval, ha='center', va='bottom', color='black')

            plt.tight_layout()
            st.pyplot(fig)

            st.subheader('After Risk Appetite')

            risk_appetite = st.session_state.get('risk_appetite', [])
            mask = (~filtered_data['inherent_risk_rating'].isin(risk_appetite)) & \
                   (~filtered_data['residual_risk_rating'].isin(risk_appetite))
            risk_register = filtered_data[mask]

            risk_rating_counts = risk_register['inherent_risk_rating'].value_counts()

            critical_count = risk_rating_counts.get('Critical', 0)
            severe_count = risk_rating_counts.get('Severe', 0)
            moderate_count = risk_rating_counts.get('Moderate', 0)
            sustainable_count = risk_rating_counts.get('Sustainable', 0)

            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("Critical Inherent Risks", critical_count)
            with col2:
                st.metric("Severe Inherent Risks", severe_count)
            with col3:
                st.metric("Moderate Inherent Risks", moderate_count)
            with col4:
                st.metric("Sustainable Inherent Risks", sustainable_count)

            style_metric_cards(border_left_color="#DBF227")

            residual_risk_rating_counts = risk_register['residual_risk_rating'].value_counts()

            residual_critical_count = residual_risk_rating_counts.get('Critical', 0)
            residual_severe_count = residual_risk_rating_counts.get('Severe', 0)
            residual_moderate_count = residual_risk_rating_counts.get('Moderate', 0)
            residual_sustainable_count = residual_risk_rating_counts.get('Sustainable', 0)

            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("Critical Residual Risks", residual_critical_count)
            with col2:
                st.metric("Severe Residual Risks", residual_severe_count)
            with col3:
                st.metric("Moderate Residual Risks", residual_moderate_count)
            with col4:
                st.metric("Sustainable Residual Risks", residual_sustainable_count)

            style_metric_cards(border_left_color="#DBF227")

            risk_type_counts = risk_register['risk_type'].value_counts()

            fig = plt.figure(figsize=(10, 6))
            bars = plt.bar(risk_type_counts.index, risk_type_counts.values, color='skyblue')
            plt.title("Risk Types Count")
            plt.ylabel("Count")
            plt.xticks(rotation=45)

            for bar in bars:
                yval = bar.get_height()
                plt.text(bar.get_x() + bar.get_width()/2, yval - 0.5, yval, ha='center', va='bottom', color='black')

            plt.tight_layout()
            st.pyplot(fig)
       
        elif tab == 'Risks Owners & Control Owners':
            st.markdown("""
            <style>
                body .stMetric span:first-child {
                    font-size: 12px !important; 
                }
                body .stMetric span:last-child {
                    font-size: 16px !important;
                }
            </style>
            """, unsafe_allow_html=True)

            if 'risk_data' not in st.session_state:
                st.session_state['risk_data'] = fetch_all_from_risk_data()

            st.subheader('Risks Owners & Control Owners')
            
            st.subheader('Date Filters')

            risk_data = st.session_state['risk_data']

            # Ensure 'date_last_updated' is in datetime format
            risk_data['date_last_updated'] = pd.to_datetime(risk_data['date_last_updated'])

            # Date filter section
            min_date = risk_data['date_last_updated'].min().date()
            max_date = risk_data['date_last_updated'].max().date()

            from_date = st.date_input('From', value=min_date, min_value=min_date, max_value=max_date)
            to_date = st.date_input('To', value=max_date, min_value=min_date, max_value=max_date)

            # Apply date filter to the data
            filtered_data = risk_data[(risk_data['date_last_updated'] >= pd.Timestamp(from_date)) &
                                      (risk_data['date_last_updated'] <= pd.Timestamp(to_date))]

            # Plotting Risk Owners Count
            risk_owners_counts = filtered_data['risk_owners'].value_counts()

            fig = plt.figure(figsize=(10, 6))
            bars = plt.bar(risk_owners_counts.index, risk_owners_counts.values, color='skyblue')
            plt.title("Risk Owners Count")
            plt.ylabel("Risk Count")
            plt.xticks(rotation=45)

            for bar in bars:
                yval = bar.get_height()
                plt.text(bar.get_x() + bar.get_width()/2, yval - 0.5, yval, ha='center', va='bottom', color='black')

            plt.tight_layout()
            st.pyplot(fig)

            # Plotting Risk Control Owners Count
            risk_control_owners_counts = filtered_data['control_owners'].value_counts()

            fig = plt.figure(figsize=(10, 6))
            bars = plt.bar(risk_control_owners_counts.index, risk_control_owners_counts.values, color='skyblue')
            plt.title("Risk Control Owners Count")
            plt.ylabel("Risk Count")
            plt.xticks(rotation=45)

            for bar in bars:
                yval = bar.get_height()
                plt.text(bar.get_x() + bar.get_width()/2, yval - 0.5, yval, ha='center', va='bottom', color='black')

            plt.tight_layout()
            st.pyplot(fig)
                   
        elif tab == 'Adjusted Risk Matrices':
            color_mapping = {
                "Critical": "red",
                "Severe": "orange",
                "Moderate": "yellow",
                "Sustainable": "green",
                None: "white"
            }

            def plot_risk_matrix_with_axes_labels(matrix, risk_matrix, title, master_risk_matrix=None):
                fig = plt.figure(figsize=(10, 10))
                plt.subplots_adjust(wspace=0, hspace=0)
                plt.xticks([0.5, 1.5, 2.5, 3.5, 4.5], ['Very Low', 'Low', 'Medium', 'High', 'Very High'])
                plt.yticks([0.5, 1.5, 2.5, 3.5, 4.5], ['Very Low', 'Low', 'Medium', 'High', 'Very High'])
                plt.xlim(0, 5)
                plt.ylim(0, 5)
                plt.xlabel('Impact')
                plt.ylabel('Probability')
                plt.title(title)

                nrows = 5
                ncols = 5
                axes = [fig.add_subplot(nrows, ncols, r * ncols + c + 1) for r in range(0, nrows) for c in range(0, ncols)]

                for r in range(0, nrows):
                    for c in range(0, ncols):
                        ax = axes[r * ncols + c]
                        ax.set_xticks([])
                        ax.set_yticks([])
                        ax.set_xlim(0, 5)
                        ax.set_ylim(0, 5)

                        cell_value = risk_matrix[r, c]
                        if cell_value not in color_mapping:
                            st.write(f"Unexpected value '{cell_value}' in risk_matrix at ({r}, {c}). Using default color.")
                            cell_value = None

                        ax.set_facecolor(color_mapping[cell_value])

                        if matrix[r, c] > 0:
                            ax.text(2.5, 2.5, str(matrix[r, c]), ha='center', va='center', fontsize=10, weight='bold')

                legend_handles = [Line2D([0], [0], color=color_mapping[key], lw=4, label=key) for key in color_mapping if key is not None]
                plt.legend(handles=legend_handles, loc='center left', bbox_to_anchor=(1, 0.5))

                plt.tight_layout()
                st.pyplot(fig)
                
            st.subheader('Date Filters')

            # Load or fetch data
            risk_data = st.session_state.get('risk_data', fetch_all_from_risk_data())

            # Ensure 'date_last_updated' is in datetime format
            risk_data['date_last_updated'] = pd.to_datetime(risk_data['date_last_updated'])

            # Date filter section
            min_date = risk_data['date_last_updated'].min().date()
            max_date = risk_data['date_last_updated'].max().date()

            from_date = st.date_input('From', value=min_date, min_value=min_date, max_value=max_date)
            to_date = st.date_input('To', value=max_date, min_value=min_date, max_value=max_date)

            # Apply date filter to the data
            filtered_data = risk_data[(risk_data['date_last_updated'] >= pd.Timestamp(from_date)) &
                                      (risk_data['date_last_updated'] <= pd.Timestamp(to_date))]

            st.header('Adjusted Risk Matrices')
            st.subheader('Before Risk Appetite')

            probability_mapping = {
                "Very Low": 1,
                "Low": 2,
                "Medium": 3,
                "High": 4,
                "Very High": 5
            }

            required_columns = [
                'inherent_risk_probability', 'inherent_risk_impact',
                'residual_risk_probability', 'residual_risk_impact'
            ]

            missing_columns = [col for col in required_columns if col not in filtered_data.columns]
            if missing_columns:
                st.error(f"Missing columns in risk_data: {', '.join(missing_columns)}")
                return

            filtered_data['inherent_risk_probability_num'] = filtered_data['inherent_risk_probability'].map(probability_mapping)
            filtered_data['inherent_risk_impact_num'] = filtered_data['inherent_risk_impact'].map(probability_mapping)
            filtered_data['residual_risk_probability_num'] = filtered_data['residual_risk_probability'].map(probability_mapping)
            filtered_data['residual_risk_impact_num'] = filtered_data['residual_risk_impact'].map(probability_mapping)

            inherent_risk_matrix = np.empty((5, 5), dtype=object)
            residual_risk_matrix = np.empty((5, 5), dtype=object)
            inherent_risk_count_matrix = np.zeros((5, 5), dtype=int)
            residual_risk_count_matrix = np.zeros((5, 5), dtype=int)

            for _, row in filtered_data.iterrows():
                prob_num = row.get('inherent_risk_probability_num')
                impact_num = row.get('inherent_risk_impact_num')
                inherent_risk_rating = row.get('inherent_risk_rating')
                if prob_num and impact_num and inherent_risk_rating in color_mapping:
                    inherent_risk_matrix[5 - prob_num, impact_num - 1] = inherent_risk_rating
                    inherent_risk_count_matrix[5 - prob_num, impact_num - 1] += 1

                prob_num = row.get('residual_risk_probability_num')
                impact_num = row.get('residual_risk_impact_num')
                residual_risk_rating = row.get('residual_risk_rating')
                if prob_num and impact_num and residual_risk_rating in color_mapping:
                    residual_risk_matrix[5 - prob_num, impact_num - 1] = residual_risk_rating
                    residual_risk_count_matrix[5 - prob_num, impact_num - 1] += 1

            master_risk_matrix = np.array([
                ["Moderate", "Severe", "Severe", "Critical", "Critical"],
                ["Moderate", "Moderate", "Severe", "Critical", "Critical"],
                ["Sustainable", "Moderate", "Severe", "Severe", "Critical"],
                ["Sustainable", "Sustainable", "Moderate", "Severe", "Critical"],
                ["Sustainable", "Sustainable", "Moderate", "Moderate", "Severe"]
            ])

            for i in range(5):
                for j in range(5):
                    if not inherent_risk_matrix[i, j]:
                        inherent_risk_matrix[i, j] = master_risk_matrix[i, j]
                    if not residual_risk_matrix[i, j]:
                        residual_risk_matrix[i, j] = master_risk_matrix[i, j]

            plot_risk_matrix_with_axes_labels(inherent_risk_count_matrix, inherent_risk_matrix, "Inherent Risk Matrix with Counts")
            plot_risk_matrix_with_axes_labels(residual_risk_count_matrix, residual_risk_matrix, "Residual Risk Matrix with Counts")

            st.subheader('After Risk Appetite')

            risk_appetite = st.session_state.get('risk_appetite', [])
            mask = (~filtered_data['inherent_risk_rating'].isin(risk_appetite)) & \
                   (~filtered_data['residual_risk_rating'].isin(risk_appetite))
            risk_register = filtered_data[mask]

            risk_register['inherent_risk_probability_num'] = risk_register['inherent_risk_probability'].map(probability_mapping)
            risk_register['inherent_risk_impact_num'] = risk_register['inherent_risk_impact'].map(probability_mapping)
            risk_register['residual_risk_probability_num'] = risk_register['residual_risk_probability'].map(probability_mapping)
            risk_register['residual_risk_impact_num'] = risk_register['residual_risk_impact'].map(probability_mapping)

            inherent_risk_matrix = np.empty((5, 5), dtype=object)
            residual_risk_matrix = np.empty((5, 5), dtype=object)
            inherent_risk_count_matrix = np.zeros((5, 5), dtype=int)
            residual_risk_count_matrix = np.zeros((5, 5), dtype=int)

            for _, row in risk_register.iterrows():
                prob_num = row.get('inherent_risk_probability_num')
                impact_num = row.get('inherent_risk_impact_num')
                inherent_risk_rating = row.get('inherent_risk_rating')
                if prob_num and impact_num and inherent_risk_rating in color_mapping:
                    inherent_risk_matrix[5 - prob_num, impact_num - 1] = inherent_risk_rating
                    inherent_risk_count_matrix[5 - prob_num, impact_num - 1] += 1

                prob_num = row.get('residual_risk_probability_num')
                impact_num = row.get('residual_risk_impact_num')
                residual_risk_rating = row.get('residual_risk_rating')
                if prob_num and impact_num and residual_risk_rating in color_mapping:
                    residual_risk_matrix[5 - prob_num, impact_num - 1] = residual_risk_rating
                    residual_risk_count_matrix[5 - prob_num, impact_num - 1] += 1

            for i in range(5):
                for j in range(5):
                    if not inherent_risk_matrix[i, j]:
                        inherent_risk_matrix[i, j] = master_risk_matrix[i, j]
                    if not residual_risk_matrix[i, j]:
                        residual_risk_matrix[i, j] = master_risk_matrix[i, j]

            plot_risk_matrix_with_axes_labels(inherent_risk_count_matrix, inherent_risk_matrix, "Inherent Risk Matrix with Counts")
            plot_risk_matrix_with_axes_labels(residual_risk_count_matrix, residual_risk_matrix, "Residual Risk Matrix with Counts")
            
        elif tab == 'Delete Risk':
            st.subheader('Delete Risk from Risk Data')
            if not st.session_state['risk_data'].empty:
                risk_to_delete = st.selectbox('Select a risk to delete', fetch_all_from_risk_data()['risk_description'].tolist())
                if st.button('Delete Risk'):
                    initial_count = len(st.session_state['risk_data'])
                    delete_from_risk_data_by_risk_description(risk_to_delete)
                    st.session_state['risk_data'] = fetch_all_from_risk_data()
                    if len(st.session_state['risk_data']) < initial_count:
                        st.write("Risk deleted.")
            else:
                st.write("No risks to delete.")
                              
        elif tab == 'Update Risk':
            st.subheader('Update Risk in Risk Data')
            if not st.session_state['risk_data'].empty:
                risk_to_update = st.selectbox('Select a risk to update', fetch_all_from_risk_data()['risk_description'].tolist())
                selected_risk_row = st.session_state['risk_data'][st.session_state['risk_data']['risk_description'] == risk_to_update].iloc[0]
                updated_risk_description = st.text_input('risk_description', value=selected_risk_row['risk_description'])
                updated_cause_consequences = st.text_input('cause_consequences', value=selected_risk_row['cause_consequences'])
                updated_risk_owners = st.text_input('risk_owners', value=selected_risk_row['risk_owners'])
                updated_inherent_risk_probability = st.selectbox('inherent_risk_probability', list(risk_levels.keys()), index=list(risk_levels.keys()).index(selected_risk_row['inherent_risk_probability']))
                updated_inherent_risk_impact = st.selectbox('inherent_risk_impact', list(risk_levels.keys()), index=list(risk_levels.keys()).index(selected_risk_row['inherent_risk_impact']))
                updated_controls = st.text_input('controls', value=selected_risk_row['controls'])
                updated_control_owners = st.text_input('control_owners', value=selected_risk_row['control_owners'])
                updated_residual_risk_probability = st.selectbox('residual_risk_probability', list(risk_levels.keys()), index=list(risk_levels.keys()).index(selected_risk_row['residual_risk_probability']))
                updated_residual_risk_impact = st.selectbox('residual_risk_impact', list(risk_levels.keys()), index=list(risk_levels.keys()).index(selected_risk_row['residual_risk_impact']))
                updated_by = st.text_input('updated_by', value=selected_risk_row['updated_by'])
                updated_date_last_updated = st.date_input('date_last_updated', value=selected_risk_row['date_last_updated'])

                if st.button('Update Risk'):
                    updated_risk = {
                        'risk_type': st.session_state['risk_type'],
                        'updated_by': updated_by,
                        'date_last_updated': updated_date_last_updated.strftime('%Y-%m-%d'),
                        'risk_description': updated_risk_description,
                        'cause_consequences': updated_cause_consequences,
                        'risk_owners': updated_risk_owners,
                        'inherent_risk_probability': updated_inherent_risk_probability,
                        'inherent_risk_impact': updated_inherent_risk_impact,
                        'inherent_risk_rating': calculate_risk_rating(updated_inherent_risk_probability, updated_inherent_risk_impact),
                        'controls': updated_controls,
                        'control_owners': updated_control_owners,
                        'residual_risk_probability': updated_residual_risk_probability,
                        'residual_risk_impact': updated_residual_risk_impact,
                        'residual_risk_rating': calculate_risk_rating(updated_residual_risk_probability, updated_residual_risk_impact)
                    }

                    old_data = st.session_state['risk_data'].copy()
                    update_risk_data_by_risk_description(risk_to_update, updated_risk)
                    st.session_state['risk_data'] = fetch_all_from_risk_data()
                    if not old_data.equals(st.session_state['risk_data']):
                        st.write("Risk updated.")
            else:
                st.write("No risks to update.")

if __name__ == '__main__':
    main()
        

