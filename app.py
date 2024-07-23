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
import datetime
import bcrypt
import mysql.connector  # Assuming you've installed mysql-connector-python
from datetime import datetime
from matplotlib.patches import Patch
from matplotlib.lines import Line2D

# Database connection
# def connect_to_db():
#     try:
#         connection = mysql.connector.connect(
#             host='localhost',
#             user='root',
#             password='ruvimboML55AMG',
#             ssl_disabled=True,
#             database='riskassessment'
#         )
#         return connection
#     except mysql.connector.Error as err:
#         st.sidebar.warning(f"Error: {err}")
#         return None
    
def connect_to_db():
    try:
        connection = mysql.connector.connect(
            host='pmsanalytics.mysql.database.azure.com',
            user='chitemerere',
            password='ruvimboML55AMG%',
            ssl_disabled=False,
            database='riskassessment',
            port = 3306,
            ssl_ca="DigiCertGlobalRootCA.crt.pem"
        )
        return connection
    except mysql.connector.Error as err:
        st.sidebar.warning(f"Error: {err}")
        return None

   
def fetch_risk_register_from_db():
    connection = connect_to_db()
    if connection:
        query = "SELECT * FROM risk_register"
        df = pd.read_sql(query, connection)
        connection.close()
        return df
    return pd.DataFrame(columns=fetch_columns_from_risk_data())  # return an empty dataframe with the right columns if there's a connection issue
  
# Add a function to fetch columns of risk_data table.
def fetch_columns_from_risk_data():
    connection = connect_to_db()
    if connection:
        cursor = connection.cursor()
        cursor.execute("DESCRIBE risk_data")
        columns = [column[0] for column in cursor.fetchall()]
        cursor.close()
        connection.close()
        return columns
    return []

# Function to insert uploaded data into risk_data table
def insert_uploaded_data_to_db(dataframe):
    connection = connect_to_db()
    if connection:
        cursor = connection.cursor()
        for _, row in dataframe.iterrows():
            # Transform 'date_last_updated' to a valid date before inserting
            try:
                date_last_updated = datetime.strptime(row['date_last_updated'], '%Y-%m-%d').date()
            except ValueError:
                date_last_updated = None  # Handle invalid dates
            sql = "INSERT INTO risk_data (risk_description, risk_type, updated_by, date_last_updated, cause_consequences, risk_owners, inherent_risk_probability, inherent_risk_impact, inherent_risk_rating, control_owners, residual_risk_probability, residual_risk_impact, residual_risk_rating, controls) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
            cursor.execute(sql, (
                row['risk_description'], row['risk_type'], row['updated_by'], row['date_last_updated'],
                row['cause_consequences'], row['risk_owners'], row['inherent_risk_probability'],
                row['inherent_risk_impact'], row['inherent_risk_rating'], row['control_owners'],
                row['residual_risk_probability'], row['residual_risk_impact'], row['residual_risk_rating'],
                row['controls']
            ))
        connection.commit()
        cursor.close()
        connection.close()

    
# Create CRUD functions for the risk_data table... 
def insert_into_risk_data(data):
    connection = connect_to_db()
    if connection:
        cursor = connection.cursor()
        placeholders = ', '.join(['%s'] * len(data))
        columns = ', '.join([f"`{key}`" for key in data.keys()])  # Surround column names with backticks
        sql = f"INSERT INTO risk_data ({columns}) VALUES ({placeholders})"
        try:
            cursor.execute(sql, list(data.values()))
            connection.commit()
        except Exception as e:
            st.write(f"Error during insertion to risk_data: {e}")  # Debugging statement
        finally:
            cursor.close()
            connection.close()

def fetch_all_from_risk_data():
    connection = connect_to_db()
    query = "SELECT * FROM risk_data"
    data = pd.read_sql(query, connection)
#     st.write("Fetched data:", data)  # Debugging statement
    connection.close()
    return data

def update_risk_data_by_risk_description(risk_description, data):
    connection = connect_to_db()
    if connection:
        cursor = connection.cursor()
        set_clause = ", ".join([f"`{key}` = %s" for key in data.keys()])
        values = list(data.values()) + [risk_description]
        sql = f"UPDATE risk_data SET {set_clause} WHERE risk_description = %s"
        cursor.execute(sql, values)
        connection.commit()
        cursor.close()
        connection.close()


def delete_from_risk_data_by_risk_description(risk_description):
    connection = connect_to_db()
#     rows_affected = 0
    if connection:
        cursor = connection.cursor()
        sql = "DELETE FROM risk_data WHERE TRIM(risk_description) = %s"
        cursor.execute(sql, (risk_description,))
        connection.commit()
        cursor.close()
        connection.close()
        affected_rows = cursor.rowcount
        print(f"Rows affected by delete operation: {affected_rows}")
#         print(f"Rows affected by delete operation: {rows_affected}")

        
def get_risk_id_by_description(risk_description):
    connection = connect_to_db()
    risk_id = None
    if connection:
        cursor = connection.cursor()
        sql = "SELECT id FROM risk_data WHERE TRIM(risk_description) = %s"
        cursor.execute(sql, (risk_description,))
        result = cursor.fetchone()
        
        
        if result:
            risk_id = result[0]
        cursor.close()
        connection.close()
    return risk_id

        
def fetch_risks_outside_appetite_from_risk_data(risk_appetite):
    connection = connect_to_db()
    data = pd.DataFrame()
    if connection:
        cursor = connection.cursor(dictionary=True)
        placeholders = ', '.join(['%s'] * len(risk_appetite))
        sql = f"SELECT * FROM risk_data WHERE residual_risk_rating NOT IN ({placeholders})"
        cursor.execute(sql, risk_appetite)
        data = pd.DataFrame(cursor.fetchall())
        cursor.close()
        connection.close()
    return data


# Create CRUD functions for the risk_register table...
def insert_risks_into_risk_register(data):
    connection = connect_to_db()
    if connection:
        cursor = connection.cursor()
        placeholders = ', '.join(['%s'] * len(data))
        columns = ', '.join(data.keys())
        sql = f"INSERT INTO risk_register ({columns}) VALUES ({placeholders})"
        try:
            cursor.execute(sql, list(data.values()))
            connection.commit()
        except Exception as e:
            st.write(f"Error during insertion: {e}")
        cursor.close()
        connection.close()


def fetch_all_from_risk_register():
    connection = connect_to_db()
    data = pd.DataFrame()
    if connection:
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT * FROM risk_register")
        data = pd.DataFrame(cursor.fetchall())
        cursor.close()
        connection.close()
    return data

def update_risk_register_by_risk_description(risk_description, data):
    connection = connect_to_db()
    if connection:
        cursor = connection.cursor()
        set_clause = ", ".join([f"{key} = %s" for key in data.keys()])
        values = list(data.values()) + [risk_description]
        sql = f"UPDATE risk_register SET {set_clause} WHERE risk_description = %s"
        cursor.execute(sql, values)
        connection.commit()
        cursor.close()
        connection.close()

def delete_from_risk_register_by_risk_description(risk_description):
    connection = connect_to_db()
    if connection:
        cursor = connection.cursor()
        sql = f"DELETE FROM risk_register WHERE risk_description = %s"
        cursor.execute(sql, (risk_description,))
        connection.commit()
        cursor.close()
        connection.close()
        
# Login function
def login(username, password):
    connection = connect_to_db()
    if connection:
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT password FROM credentials WHERE username = %s", (username,))
        row = cursor.fetchone()
        cursor.close()
        connection.close()
        if row:
            hashed_password = row['password'].encode('utf-8')
            return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
    return False

def register(username, password):
    connection = connect_to_db()
    if connection:
        cursor = connection.cursor(dictionary=True)
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        try:
            cursor.execute("INSERT INTO credentials (username, password) VALUES (%s, %s)", (username, hashed_password))
            connection.commit()
            cursor.close()
            connection.close()
            return True
        except mysql.connector.Error as err:
            st.sidebar.warning(f"Error: {err}")
            return False
        
def main():
  
    st.markdown('### Enterprise Risk Management Application')
    st.image("logo.png", width=200)

    # Check if 'logged_in' is in session state
    if 'logged_in' not in st.session_state:
        st.session_state.logged_in = False

    # If not logged in, show the login and registration interface
    if not st.session_state.logged_in:
        # Login
        st.sidebar.subheader("Login")
        username = st.sidebar.text_input("Username")
        password = st.sidebar.text_input("Password", type="password")
        if st.sidebar.button("Login"):
            if login(username, password):
                st.sidebar.success("Logged in successfully!")
                st.session_state.logged_in = True  # Set logged_in to True
            else:
                st.sidebar.error("Invalid credentials")

        # Registration
        st.sidebar.subheader("Register")
        new_username = st.sidebar.text_input("New Username", key='reg_username')
        new_password = st.sidebar.text_input("New Password", type="password", key='reg_password')
        if st.sidebar.button("Register"):
            if register(new_username, new_password):
                st.sidebar.success("Registered successfully! You can now login.")
            else:
                st.sidebar.error("Registration failed. Perhaps the username is already taken.")
    else:

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

            green = [10, 15, 16, 20, 21]  # Green boxes
            yellow = [0, 5, 6, 11, 17, 22, 23]  # Yellow boxes
            orange = [1, 2, 7, 12, 13, 18, 24]  # Orange boxes
            red = [3, 4, 8, 9, 14, 19]  # Red boxes

            for _ in green:
                axes[_].set_facecolor('green')
            for _ in yellow:
                axes[_].set_facecolor('yellow')
            for _ in orange:
                axes[_].set_facecolor('orange')
            for _ in red:
                axes[_].set_facecolor('red')

            # labels for each box
            # Add labels to the Green boxes
            axes[10].text(0.1, 0.8, 'Sustainable')
            axes[15].text(0.1, 0.8, 'Sustainable')
            axes[20].text(0.1, 0.8, 'Sustainable')
            axes[16].text(0.1, 0.8, 'Sustainable')
            axes[21].text(0.1, 0.8, 'Sustainable')

            # Add labels to the Yellow boxes
            axes[0].text(0.1, 0.8, 'Moderate')
            axes[5].text(0.1, 0.8, 'Moderate')
            axes[6].text(0.1, 0.8, 'Moderate')
            axes[11].text(0.1, 0.8, 'Moderate')
            axes[17].text(0.1, 0.8, 'Moderate')
            axes[22].text(0.1, 0.8, 'Moderate')
            axes[23].text(0.1, 0.8, 'Moderate')

            # Add labels to the Orange boxes
            axes[1].text(0.1, 0.8, 'Severe')
            axes[2].text(0.1, 0.8, 'Severe')
            axes[7].text(0.1, 0.8, 'Severe')
            axes[12].text(0.1, 0.8, 'Severe')
            axes[13].text(0.1, 0.8, 'Severe')
            axes[18].text(0.1, 0.8, 'Severe')
            # axes[19].text(0.1, 0.8, 'Severe')
            axes[24].text(0.1, 0.8, 'Severe')

            # Add labels to the Red Boxes
            axes[3].text(0.1, 0.8, 'Critical')
            axes[8].text(0.1, 0.8, 'Critical')
            axes[4].text(0.1, 0.8, 'Critical')
            axes[9].text(0.1, 0.8, 'Critical')
            axes[14].text(0.1, 0.8, 'Critical')
            axes[19].text(0.1, 0.8, 'Critical')

            st.pyplot(fig)

        # Risk Assessment functions and variables
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
            return risk_rating_dict[(risk_levels[probability], risk_levels[impact])]
        
        # Tabs for the application
        tab = st.sidebar.selectbox(
            'Choose a function',
            ('Main Application', 'Risks Overview','Risks Owners & Control Owners','Adjusted Risk Matrices' ,'Delete Risk', 'Update Risk')
        )
        
        # Initialize the session state if it doesn't exist
        if 'risk_data' not in st.session_state:
            st.session_state['risk_data'] = fetch_risk_register_from_db()
            if st.session_state['risk_data'].empty:
                st.session_state['risk_data'] = pd.DataFrame(columns=[
                    'Risk Description', 'Cause & Consequences', 'Risk Owner(s)', 
                    'Inherent Risk Probability', 'Inherent Risk Impact', 'Inherent Risk Rating',
                    'Control(s)', 'Control Owner(s)', 
                    'Residual Risk Probability', 'Residual Risk Impact', 'Residual Risk Rating'
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

        # Main Application Tab
        if tab == 'Main Application':
            # Check and fetch data if not in session_state
            if 'risk_data' not in st.session_state:
                st.session_state['risk_data'] = fetch_all_from_risk_data()
            # Display the Master Risk Matrix
            st.subheader('Master Risk Matrix')
            plot_risk_matrix()
            
            
            # File uploader and handling the uploaded file
            st.sidebar.subheader('Upload Risk Data')
            uploaded_file = st.sidebar.file_uploader("Choose a CSV file", type="csv")
            if uploaded_file:
                if st.sidebar.button("Upload"):
                    data = pd.read_csv(uploaded_file)

                    # Check if the necessary columns exist
                    if set(['risk_description','risk_type','updated_by','date_last_updated','cause_consequences','risk_owners','inherent_risk_probability','inherent_risk_impact','inherent_risk_rating','control_owners','residual_risk_probability','residual_risk_impact','residual_risk_rating' ,'controls']).issubset(data.columns):
                        # Insert data into the database
                        insert_uploaded_data_to_db(data)
                        st.sidebar.success("Data uploaded successfully!")
                    else:
                        st.sidebar.error("The uploaded file does not have the required columns")
            

            # Risk Assessment Application
            st.subheader('Enter Risk Details')

            # Initialize risk_appetite if not present
            if 'risk_appetite' not in st.session_state:
                st.session_state['risk_appetite'] = ['Critical', 'Severe', 'Moderate', 'Sustainable']

            # New multi-select for Risk Appetite
            selected_appetite = st.multiselect(
                'Risk Appetite', 
                ['Critical', 'Severe', 'Moderate', 'Sustainable'], 
                default=st.session_state['risk_appetite']
            )
            st.session_state['risk_appetite'] = selected_appetite

            st.session_state['risk_type'] = st.selectbox('Risk Type', ['Strategic risk', 'Operational risks', 'Organizational risks', 'Reputation risks', 'Market risks', 'Compliance & Regulatory risks', 'Hazard risks','Financial risks' ,'Project risks'])
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

            # Display the risk data
            st.subheader('Risk Data')
            

            st.session_state['risk_data'] = fetch_all_from_risk_data()
            st.write(st.session_state['risk_data'])

            # Download Risk Data
            if not st.session_state['risk_data'].empty:
                csv = st.session_state['risk_data'].to_csv(index=False)
                current_datetime = datetime.now().strftime('%Y%m%d%H%M%S')  # Format: YYYYMMDDHHMMSS
                st.download_button(
                    label="Download Risk Data",
                    data=csv,
                    file_name=f"risk_data_{current_datetime}.csv",
                    mime="text/csv",
                )
            else:
                st.write("No risk data available to download.")

            # Display Risk Register
            st.subheader('Risk Register')
            risk_appetite = st.session_state.get('risk_appetite', [])
            mask = (~st.session_state['risk_data']['inherent_risk_rating'].isin(risk_appetite)) & (~st.session_state['risk_data']['residual_risk_rating'].isin(risk_appetite))
            risk_register = st.session_state['risk_data'][mask]
            st.write(risk_register)

            # Download Risk Register
            if not risk_register.empty:
                csv_register = risk_register.to_csv(index=False)
                current_datetime = datetime.now().strftime('%Y%m%d%H%M%S')  # Format: YYYYMMDDHHMMSS
                st.download_button(
                    label="Download Risk Register",
                    data=csv_register,
                    file_name=f"risk_register_{current_datetime}.csv",
                    mime="text/csv",
                )
            else:
                st.write("No risk register data available to download.")
                
        elif tab == 'Risks Overview':
            # Custom CSS for adjusting metric card font size
            # Custom CSS with increased specificity
            st.markdown("""
            <style>
                /* Adjusting font size for metric card labels */
                body .stMetric span:first-child {
                    font-size: 12px !important; 
                }
                /* Adjusting font size for metric card values */
                body .stMetric span:last-child {
                    font-size: 16px !important;
                }
            </style>
            """, unsafe_allow_html=True)
                        
            # Check and fetch data if not in session_state
            if 'risk_data' not in st.session_state:
                st.session_state['risk_data'] = fetch_all_from_risk_data()
               
            st.subheader('Risks Dashboard')
            
            # 1. Load the data
            risk_data = st.session_state['risk_data']
            
            # Count inherent risk ratings
            risk_rating_counts = risk_data['inherent_risk_rating'].value_counts()

            # Define counts for each category
            critical_count = risk_rating_counts.get('Critical', 0)
            severe_count = risk_rating_counts.get('Severe', 0)
            moderate_count = risk_rating_counts.get('Moderate', 0)
            sustainable_count = risk_rating_counts.get('Sustainable', 0)
            
            
            # Display the metrics
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("Critical Inherent Risks", critical_count)
            with col2:
                st.metric("Severe Inherent Risks", severe_count)
            with col3:
                st.metric("Moderate Inherent Risks", moderate_count)
            with col4:
                st.metric("Sustainable Inherent Risks", sustainable_count)
                
                # this is used to style the metric card
                style_metric_cards(border_left_color="#DBF227")
                
            
            # Count residual risk ratings
            residual_risk_rating_counts = risk_data['residual_risk_rating'].value_counts()

            # Define counts for each category
            residual_critical_count = residual_risk_rating_counts.get('Critical', 0)
            residual_severe_count = residual_risk_rating_counts.get('Severe', 0)
            residual_moderate_count = residual_risk_rating_counts.get('Moderate', 0)
            residual_sustainable_count = residual_risk_rating_counts.get('Sustainable', 0)
            
            
            # Display the metrics
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("Critical Residual Risks", residual_critical_count)
            with col2:
                st.metric("Severe Residual Risks", residual_severe_count)
            with col3:
                st.metric("Moderate Residual Risks", residual_moderate_count)
            with col4:
                st.metric("Sustainable Residual Risks", residual_sustainable_count)
                
                # this is used to style the metric card
                style_metric_cards(border_left_color="#DBF227")
            
                        
            # Bar plot for risk types
            # Count the occurrences for each risk type
            risk_type_counts = risk_data['risk_type'].value_counts()

            # Plotting the bar chart with counts inside the bars
            fig=plt.figure(figsize=(10,6))
            bars = plt.bar(risk_type_counts.index, risk_type_counts.values, color='skyblue')
            plt.title("Risk Types Count")
            plt.ylabel("Count")
            plt.xticks(rotation=45)

            # Display counts inside the bars
            for bar in bars:
                yval = bar.get_height()
                plt.text(bar.get_x() + bar.get_width()/2, yval - 0.5, yval, ha='center', va='bottom', color='black')

            # Show the plot
            plt.tight_layout()
            st.pyplot(fig)
        ######
        elif tab == 'Risks Owners & Control Owners':
            # Custom CSS for adjusting metric card font size
            # Custom CSS with increased specificity
            st.markdown("""
            <style>
                /* Adjusting font size for metric card labels */
                body .stMetric span:first-child {
                    font-size: 12px !important; 
                }
                /* Adjusting font size for metric card values */
                body .stMetric span:last-child {
                    font-size: 16px !important;
                }
            </style>
            """, unsafe_allow_html=True)
                        
            # Check and fetch data if not in session_state
            if 'risk_data' not in st.session_state:
                st.session_state['risk_data'] = fetch_all_from_risk_data()
               
            st.subheader('Risks Owners & Control Owners')
            
            # 1. Load the data
            risk_data = st.session_state['risk_data']
            
                        
            # Bar plot for risk types
            # Count the occurrences for each risk owner
            risk_owners_counts = risk_data['risk_owners'].value_counts()

            # Plotting the bar chart with counts inside the bars
            fig=plt.figure(figsize=(10,6))
            bars = plt.bar(risk_owners_counts.index, risk_owners_counts.values, color='skyblue')
            plt.title("Risk Owners Count")
            plt.ylabel("Risk Count")
            plt.xticks(rotation=45)

            # Display counts inside the bars
            for bar in bars:
                yval = bar.get_height()
                plt.text(bar.get_x() + bar.get_width()/2, yval - 0.5, yval, ha='center', va='bottom', color='black')

            # Show the plot
            plt.tight_layout()
            st.pyplot(fig)
            
            # Bar plot for risk types
            # Count the occurrences for each Control owner
            risk_control_owners_counts = risk_data['control_owners'].value_counts()

            # Plotting the bar chart with counts inside the bars
            fig=plt.figure(figsize=(10,6))
            bars = plt.bar(risk_control_owners_counts.index, risk_control_owners_counts.values, color='skyblue')
            plt.title("Risk Control Owners Count")
            plt.ylabel("Risk Count")
            plt.xticks(rotation=45)

            # Display counts inside the bars
            for bar in bars:
                yval = bar.get_height()
                plt.text(bar.get_x() + bar.get_width()/2, yval - 0.5, yval, ha='center', va='bottom', color='black')

            # Show the plot
            plt.tight_layout()
            st.pyplot(fig)
        ######
        elif tab == 'Adjusted Risk Matrices':
            # Define the color_mapping dictionary
            color_mapping = {
                "Critical": "red",
                "Severe": "orange",
                "Moderate": "yellow",
                "Sustainable": "green",
                None: "white"  # For cells with no risk rating
            }

            def plot_risk_matrix_with_axes_labels(matrix, risk_matrix, title, master_risk_matrix=None):
                fig = plt.figure(figsize=(10,10))
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

                        if risk_matrix[r, c] is None and master_risk_matrix is not None:
                            ax.set_facecolor(color_mapping[master_risk_matrix[r, c]])
                        else:
                            ax.set_facecolor(color_mapping[risk_matrix[r, c]])

                        if matrix[r, c] > 0:
                            ax.text(2.5, 2.5, str(matrix[r, c]), ha='center', va='center', fontsize=10, weight='bold')

                legend_handles = [Line2D([0], [0], color=color_mapping[key], lw=4, label=key) for key in color_mapping if key is not None]
                plt.legend(handles=legend_handles, loc='center left', bbox_to_anchor=(1, 0.5))

                plt.tight_layout()
                st.pyplot(fig)

            # Load the data
            risk_data = st.session_state.get('risk_data', fetch_all_from_risk_data())
            st.subheader('Adjusted Risk Matrices')

            # Convert risk probabilities and impacts to numeric scales
            probability_mapping = {
                "Very Low": 1,
                "Low": 2,
                "Medium": 3,
                "High": 4,
                "Very High": 5
            }

            risk_data['inherent_risk_probability_num'] = risk_data['inherent_risk_probability'].map(probability_mapping)
            risk_data['inherent_risk_impact_num'] = risk_data['inherent_risk_impact'].map(probability_mapping)
            risk_data['residual_risk_probability_num'] = risk_data['residual_risk_probability'].map(probability_mapping)
            risk_data['residual_risk_impact_num'] = risk_data['residual_risk_impact'].map(probability_mapping)
            
            # Initialize 5 x 5 grid for inherent and residual risks
            inherent_risk_matrix = np.empty((5, 5), dtype=object)
            residual_risk_matrix = np.empty((5, 5), dtype=object)
            inherent_risk_count_matrix = np.zeros((5, 5), dtype=int)
            residual_risk_count_matrix = np.zeros((5, 5), dtype=int)
            
            
            # Use value_counts to count inherent and residual risk ratings
            inherent_risk_counts = risk_data['inherent_risk_rating'].value_counts()
            residual_risk_counts = risk_data['residual_risk_rating'].value_counts()

                      
            for _, row in risk_data.iterrows():
                # Inherent risk matrix
                prob_num = row['inherent_risk_probability_num']
                impact_num = row['inherent_risk_impact_num']
                inherent_risk_matrix[5 - prob_num, impact_num - 1] = row['inherent_risk_rating']
                inherent_risk_count_matrix[5 - prob_num, impact_num - 1] += 1
                
#                 prob_num_inherent = row['inherent_risk_probability_num']
#                 impact_num_inherent = row['inherent_risk_impact_num']
#                 inherent_risk_matrix[5 - prob_num_inherent, impact_num_inherent - 1] = row['inherent_risk_rating']
#                 inherent_risk_count_matrix[5 - prob_num_inherent, impact_num_inherent - 1] += 1

                # Residual risk matrix
                prob_num = row['residual_risk_probability_num']
                impact_num = row['residual_risk_impact_num']
                residual_risk_matrix[5 - prob_num, impact_num - 1] = row['residual_risk_rating']
                residual_risk_count_matrix[5 - prob_num, impact_num - 1] += 1
                
                                  
            # Master Risk Matrix definition
            master_risk_matrix = np.array([
                ["Moderate", "Severe", "Severe", "Critical", "Critical"],
                ["Moderate", "Moderate", "Severe", "Critical", "Critical"],
                ["Sustainable", "Moderate", "Severe", "Severe", "Critical"],
                ["Sustainable", "Sustainable", "Moderate", "Severe", "Critical"],
                ["Sustainable", "Sustainable", "Moderate", "Moderate", "Severe"]
            ])

            # Ensure cells without a risk rating are colored according to the master risk matrix
            for i in range(5):
                for j in range(5):
                    if not inherent_risk_matrix[i, j]:
                        inherent_risk_matrix[i, j] = master_risk_matrix[i, j]
                    if not residual_risk_matrix[i, j]:
                        residual_risk_matrix[i, j] = master_risk_matrix[i, j]

            # Plot the matrices
            plot_risk_matrix_with_axes_labels(inherent_risk_count_matrix, inherent_risk_matrix, "Inherent Risk Matrix with Counts")
            plot_risk_matrix_with_axes_labels(residual_risk_count_matrix, residual_risk_matrix, "Residual Risk Matrix with Counts")
                                         
        # Delete Risk Tab
        elif tab == 'Delete Risk':
            # Delete Risk Functionality
            st.subheader('Delete Risk from Risk Data')
            if not st.session_state['risk_data'].empty:
                risk_to_delete = st.selectbox('Select a risk to delete', fetch_all_from_risk_data()['risk_description'].tolist())
                if st.button('Delete Risk'):
                    print("Delete Risk button pressed.")  # Debugging line
                    delete_from_risk_data_by_risk_description(risk_to_delete)
                    st.session_state['risk_data'] = fetch_all_from_risk_data()
                    st.write("Risk deleted.")

            else:
                st.write("No risks to delete.")

        # Update Risk Tab
        elif tab == 'Update Risk':
            # Update Risk Functionality
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
                    'date_last_updated': updated_date_last_updated.strftime('%Y-%m-%d'),  # Convert date to string format suitable for MySQL
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

                    # Call the function to update the risk in the database
                    update_risk_data_by_risk_description(risk_to_update, updated_risk)
                    st.write("Risk updated.")
                 

            else:
                st.write("No risks to update.")

if __name__ == '__main__':
    main()


# In[ ]:




