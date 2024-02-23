import re
import json
import base64
import os
from bs4 import BeautifulSoup
from typing import Dict, Optional
from datetime import datetime, timedelta

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError


# If modifying these scopes, delete the file token.json.
SCOPES = ["https://www.googleapis.com/auth/gmail.modify", "https://www.googleapis.com/auth/spreadsheets"]
TOKEN = 'token.json'
LAST_HISTORY_ID = 0
NEXT_WATCH = None
creds = None
SPREADSHEET_ID = None
TABLE_RANGE = "A1:J5"
NAMES_COLUMN = 2
STUDENT_ID_COLUMN = 5
TRANSACTION_AMOUNT = 3000
STATUS_COLUMN = 9
TOPIC_NAME = None


def update_data(data: dict) -> None:
    """
    Updates global variables based on the input data dictionary.

    Args:
        data (dict): A dictionary containing the following optional keys:
            - spreadsheet_id (str): The ID of the spreadsheet to update.
            - table_range (str): The range of cells in the spreadsheet to update.
            - names_column (int): The column index of the names column in the spreadsheet.
            - student_id_column (int): The column index of the student ID column in the spreadsheet.
            - transaction_amount (int): The transaction amount to update in the spreadsheet.
            - status_column (int): The column index of the status column in the spreadsheet.
            - topic_name (str): The name of the topic.

    Returns:
        None
    """
    global SPREADSHEET_ID, TABLE_RANGE, NAMES_COLUMN, STUDENT_ID_COLUMN, TRANSACTION_AMOUNT, STATUS_COLUMN, TOPIC_NAME

    if 'spreadsheet_id' in data:
        SPREADSHEET_ID = data["spreadsheet_id"]
    
    if 'table_range' in data:
        TABLE_RANGE = data["table_range"]

    if 'names_column' in data:    
        NAMES_COLUMN = data["names_column"]

    if 'student_id_column' in data: 
        STUDENT_ID_COLUMN = data["student_id_column"]

    if 'transaction_amount' in data: 
        TRANSACTION_AMOUNT = data["transaction_amount"]

    if 'status_column' in data: 
        STATUS_COLUMN = data["status_column"]

    if 'topic_name' in data: 
        TOPIC_NAME = data["topic_name"]

def create_credentials():
    """
    Creates the credentials file required for authentication with the Google API.

    Args:
        None

    Returns:
        None

    Raises:
        ValueError: If any of the required inputs are missing.
    """
    # Retrieve the client ID, client secret, and project ID from the environment variables
    client_id = os.environ.get('GOOGLE_CLIENT_ID')
    client_secret = os.environ.get('GOOGLE_CLIENT_SECRET')
    project_id = os.environ.get('GOOGLE_PROJECT_ID')

    # Check if any of the required inputs are missing
    if client_id is None or client_secret is None or project_id is None:
        raise ValueError("Missing required environment variables")

    # Create the credentials dictionary
    credentials = {
        "installed": {
            "client_id": client_id,
            "project_id": project_id,
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
            "client_secret": client_secret,
            "redirect_uris": ["http://localhost"]
        }
    }

    return credentials

def check_credentials(cred):
    global creds
    if os.path.exists(TOKEN):
        creds = Credentials.from_authorized_user_file(TOKEN)  # Path to your credentials file    
    # If there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_config(cred, SCOPES)
            creds = flow.run_local_server(port=0)
            # Save the credentials for the next run
        with open(TOKEN, "w") as token:
            token.write(creds.to_json())

def naira_to_float(amount: str) -> float:
    """
    Converts a string representing a Nigerian Naira amount to a float value.

    Args:
        amount (str): A string representing a Nigerian Naira amount, with the format "NGN X,XXX.XX".

    Returns:
        float: The converted amount as a float value.
    """
    cleaned_amount = amount.replace("NGN", "").replace(",", "")
    return round(float(cleaned_amount), 2)

# Function to fetch emails from Gmail inbox
def fetch_emails(query, max_results=10):
    """Fetch ten recent emails from the inbox.
    Takes a query parameter as a keyword to search
    """
    global creds
    try:
        # Call the Gmail API
        service = build('gmail', 'v1', credentials=creds)
        response = service.users().messages().list(userId='me', q=query, maxResults=max_results).execute()
        messages = []
        if 'messages' in response:
            messages.extend(response['messages'])
        while 'nextPageToken' in response:
            page_token = response['nextPageToken']
            response = service.users().messages().list(userId='me', q=query, maxResults=max_results, pageToken=page_token).execute()
            if 'messages' in response:
                messages.extend(response['messages'])
        return messages
    except Exception as e:
        # TODO(developer) - Handle errors from gmail API.
        print(f"An error occurred: {e}")
        return None

def update_values(spreadsheet_id, range_name, value_input_option, values):
    """
    Creates the batch_update the user has access to.
    Load pre-authorized user credentials from the environment.
    """
    # pylint: disable=maybe-no-member
    global creds
    try:
      service = build("sheets", "v4", credentials=creds)
      body = {"values": values}
      result = (
          service.spreadsheets()
          .values()
          .update(
              spreadsheetId=spreadsheet_id,
              range=range_name,
              valueInputOption=value_input_option,
              body=body,
          )
          .execute()
      )
      print(f"{result.get('updatedCells')} cells updated.")
      return result
    except HttpError as error:
      print(f"An error occurred: {error}")
      return error

def get_values(spreadsheet_id, range_name):
    """
    Creates the batch_update the user has access to.
    Load pre-authorized user credentials from the environment.
    TODO(developer) - See https://developers.google.com/identity
    for guides on implementing OAuth2 for the application.
    """
    global creds
    try:
        service = build("sheets", "v4", credentials=creds)

        result = (
            service.spreadsheets()
            .values()
            .get(spreadsheetId=spreadsheet_id, range=range_name)
            .execute()
        )
        rows = result.get("values", [])
        print(f"{len(rows)} rows retrieved")
        return rows
    except HttpError as error:
        print(f"An error occurred: {error}")
        return error

# Function to retrieve email details
def get_email_details(message_id: str) -> dict:
    """
    Retrieves the details of an email message from a Gmail account using the Gmail API.

    Args:
        message_id (str): The ID of the email message to retrieve details for.

    Returns:
        dict: A dictionary containing the details of the email message, including the message ID, thread ID, labels, headers, and body.
              If an error occurs during retrieval, None is returned.
    """
    global creds
    service = build('gmail', 'v1', credentials=creds)

    try:
        message = service.users().messages().get(userId='me', id=message_id).execute()
        return message
    except Exception as e:
        print(f"An error occurred: {e}")
        return None
    
# Function to start a watch on gmail inbox
def set_watch():
    global creds
    service = build('gmail', 'v1', credentials=creds)

    try:
        body = {
            "labelIds": [
                "INBOX"
            ],
            "labelFilterBehavior": "INCLUDE",
            "topicName": TOPIC_NAME
        }
        response = service.users().watch(userId='me', body=body).execute()

        return response
    except Exception as e:
        print(f"An error occurred: {e}")
        return None
    
# Function to stop a watch on gmail inbox
def stop_watch():
    global NEXT_WATCH, creds
    service = build('gmail', 'v1', credentials=creds)

    try:
        service.users().stop(userId='me').execute()
        NEXT_WATCH = None
    except Exception as e:
        print(f"An error occurred: {e}")

# Function to decode messages
def decode_message(data: str) -> str:
    """
    Decodes a base64 encoded string and returns the decoded version.

    Args:
        data (str): The base64 encoded string to be decoded.

    Returns:
        str: The decoded version of the input base64 encoded string.
    """
    decoded_bytes = base64.urlsafe_b64decode(data)
    decoded_message = decoded_bytes.decode('utf-8')
    return decoded_message

# Function to get message body
def format_body(msg_dict, mimetype="plain"):
    """Takes email dictionary and returns the message body in specified format.\ndefault: text/plain"""
    if re.match(r"multipart", msg_dict['payload']['mimeType'], re.IGNORECASE):
        msg_parts = msg_dict['payload']["parts"]
    else:
        msg_parts = [{"mimeType": msg_dict['payload']['mimeType'], "body": msg_dict['payload']['body']}]
    for part in msg_parts:
        if part["mimeType"] == f"text/{mimetype}":
            return decode_message(part["body"]["data"])
        elif part["mimeType"] == f"multipart/alternative":
            for multipart in part["parts"]:
                if multipart["mimeType"] == f"text/{mimetype}":
                    return decode_message(multipart["body"]["data"]).strip()

            return decode_message(part["body"]["data"])
    
    return [part for part in msg_parts]

# Function to return the message body in text format
def format_header(msg_dict: Dict[str, Dict[str, list]]) -> Dict[str, str]:
    """
    Returns a dictionary containing the header information of the email.

    Args:
        msg_dict (dict): A dictionary representing an email message. It should have a 'payload' key containing a list of headers.

    Returns:
        dict: A dictionary containing the header information of the email. The keys are 'From', 'To', 'Subject', and 'Date', and the values are the corresponding header values.
    """
    my_headers = {}
    headers = msg_dict['payload']['headers']
    for header in headers:
        name = header['name']
        value = header['value']
        if name == 'From':
            my_headers['From'] = value
        elif name == 'To':
            my_headers['To'] = value
        elif name == 'Subject':
            my_headers['Subject'] = value
        elif name == 'Date':
            parsed_date = datetime.strptime(value, '%a, %d %b %Y %H:%M:%S %z')
            formatted_date = parsed_date.strftime('%a, %d %b %Y %I:%M:%S %p')
            my_headers['Date'] = formatted_date
    return my_headers


# Fuction to parse email html
# def extract_transaction_info(html_content: str, bank: str) -> Optional[Dict[str, str]]:
#     """
#     Returns a dictionary containing transaction info from email html

#     Args:
#         html_content (str): The HTML content of the email.
#         bank (str): The name of the bank from which the transaction details are extracted.

#     Returns:
#         dict: A dictionary containing the extracted transaction information.
#     """
#     transaction_info = None
#     rows = None

#     # Parse the HTML content
#     soup = BeautifulSoup(html_content, 'html.parser')

#     # Find the table containing transaction details
#     tables = soup.find_all('table')
#     for table in tables:
#         rows = table.find_all('tr')
#         for row in rows:
#             cells = row.find_all('td')
#             if len(cells) == 2:
#                 key = cells[0].get_text(strip=True).lower()
#                 value = cells[1].get_text(strip=True).lower()
#                 if "account n" in key:
#                     transaction_info = parse_bank(rows, bank)
#                     break
#         if transaction_info:
#             break

#     return transaction_info


# def parse_bank(rows, bank_name):
#     # Extract individual transaction details
#     transaction_info = {}
#     for row in rows:
#         cells = row.find_all('td')
#         if len(cells) == 2:
#             key = cells[0].get_text(strip=True).replace(':', '')
#             value = cells[1].get_text(strip=True)
#             if bank_name == "union":
#                 # Convert Transaction Amount to integer
#                 if 'Transaction Amount' in key:
#                     amount = re.sub(r'[^\d]', '', value)
#                     value = int(amount)/100 # Remove non-digit characters except for the decimal point
#                 if "Transaction Details" in key:
#                     continue
#             elif bank_name == "zenith":
#                 if 'Amount' in key:
#                     amount = re.sub(r'[^\d]', '', value)
#                     value = int(amount)/100 # Remove non-digit characters except for the decimal point
#             elif bank_name == "alat":
#                 if 'Amount' in key:
#                     amount = re.sub(r'[^\d]', '', value)
#                     value = int(amount)/100 # Remove non-digit characters except for the decimal point

#             transaction_info[key] = value

#     return transaction_info


# Function to mark an email as read
# def mark_email_as_read(email_id: str) -> None:
#     """
#     Marks an email as read in a Gmail account.

#     Args:
#         email_id (str): The ID of the email to be marked as read.

#     Returns:
#         None: The function does not return any value.
#     """
#     global creds
#     service = build('gmail', 'v1', credentials=creds)

#     try:
#         message = service.users().messages().modify(userId='me', id=email_id, body={'removeLabelIds': ['UNREAD']}).execute()
#         if message['id'] == email_id:
#             print(f"Email with ID {email_id} marked as read.")
#         else:
#             raise Exception
#     except Exception as e:
#         print(f"Error marking email as read: {e}")

def get_transaction_for_lotus_bank(html_body: str) -> Dict[str, Optional[str]]:
    """
    Extracts transaction details from an HTML email body.

    Args:
        html_body (str): The HTML body of the email.

    Returns:
        dict: A dictionary containing the extracted transaction details, including the account number, transaction details, amount, date, and balance.
    """
    soup = BeautifulSoup(html_body, 'html.parser')
    try:
        account_element = soup.find(text=re.compile(r"Account Number : (\*{6}\d{4})"))
        details_element = soup.find(text=re.compile(r"Transaction Details: (.*?)\s"))
        amount_element = soup.find(text=re.compile(r"Transaction Amount : (\w+[0-9,.]+)"))
        date_element = soup.find(text=re.compile(r"Transaction Date : (\d+ [A-Z]+ \d+ \d+:\d+:\d+)"))
        balance_element = soup.find(text=re.compile(r"Account Balance : (\w+[0-9,.]+)"))

        account = account_element.split(":")[1].strip() if account_element else ""
        details = details_element.split(":")[1].strip() if details_element else ""
        amount = amount_element.split(":")[1].strip() if amount_element else ""
        date = date_element.split(":")[1].strip() if date_element else ""
        balance = balance_element.split(":")[1].strip() if balance_element else ""

        if account == "" or details == "" or amount == "":
            return None
        amount = naira_to_float(amount)
        balance = naira_to_float(balance)

        data = {
            "account": account,
            "details": details,
            "amount": amount,
            "date": date,
            "balance": balance
        }
    except ValueError as e:
        print(f"An error occurred: {e}")
        return None

    return data

def get_credit_alert(email_id: str) -> dict or None: # type: ignore
    """
    Retrieves the details of a credit alert email.

    Args:
        email_id (str): The ID of the email to retrieve the credit alert details for.

    Returns:
        dict or None: A dictionary containing the extracted transaction details, including the account number,
        transaction details, amount, date, and balance. Returns None if the email is not a credit alert or if the
        transaction details cannot be extracted.
    """
    raw_email = get_email_details(email_id)
    email_headers = format_header(raw_email)

    if raw_email and email_headers.get("From") == "notifications@lotusbank.com":
        email_body_html = format_body(raw_email, "html")
        transaction_details = get_transaction_for_lotus_bank(email_body_html)
        print("Credit alert processed!")
        return transaction_details

    return None

# def get_credit_alerts(max_num: int) -> list[Dict[str, any]]:
#     """
#     Fetches a specified number of emails with the subject "Account Credited" and extracts the transaction details.
    
#     Args:
#         max_num (int): The maximum number of emails to fetch and process.
        
#     Returns:
#         List[Dict[str, Any]]: A list containing the extracted transaction details from the fetched emails.
#     """
#     found_emails = []
#     emails = fetch_emails("subject: Account Credited", max_num)
#     for email in emails:
#         message_id = email['id']
#         transaction_details = get_credit_alert(message_id)
#         found_emails.append(transaction_details)
#     return found_emails

def get_pending_payments() -> Optional[list[Dict[str, str]]]:
    """
    Retrieves data from a Google Sheets spreadsheet and returns a list of users who have pending payments.

    Returns:
        A list of dictionaries, where each dictionary represents a user with pending payments. Each dictionary contains the user's name and student ID.
    """
    table = get_values(SPREADSHEET_ID, TABLE_RANGE)
    users = []
    if not table:
      return None
    for num, row in enumerate(table):
        if num == 0:
            continue
        if len(row) == STATUS_COLUMN:
            if num == 0:
                row.append("Payment Status")
            else:
                row.append("-")
            update_values(SPREADSHEET_ID, TABLE_RANGE, "RAW", table)
        elif len(row) == STATUS_COLUMN-1:
            row.append(" ")
            row.append("-")
            update_values(SPREADSHEET_ID, TABLE_RANGE, "RAW", table)
        if row[STATUS_COLUMN] != "PAID":
            users.append({
                "name": row[NAMES_COLUMN],
                "student id": row[STUDENT_ID_COLUMN]
            })
    if users:
        print("Pending payments found!")
    return users


# Function to get email ids
def get_id(response):
    """
    Retrieves the ID of the last message added to a Gmail inbox.

    Args:
        response (dict): A dictionary containing a 'message' key with a 'data' value. The 'data' value is expected to be a base64-encoded string.

    Returns:
        str: The ID of the last message added to the Gmail inbox.
    """
    global LAST_HISTORY_ID, creds
    try:
        data = response["message"]["data"]
        event = decode_message(data)
        event_data = json.loads(event)
        history_id = int(event_data["historyId"])
        if LAST_HISTORY_ID != 0:
            history_id = LAST_HISTORY_ID
        else:
            history_id -= 100

        service = build('gmail', 'v1', credentials=creds)

        response = service.users().history().list(
            userId='me',
            maxResults=10,
            historyTypes="messageAdded",
            labelId="INBOX",
            startHistoryId=history_id
        ).execute()

        messages = response.get("history", [])
        last_message = None

        for message in messages:
            message_id = message["messagesAdded"][0]["message"]["id"]
            if last_message is None or message_id > last_message:
                last_message = message_id               
        LAST_HISTORY_ID = int(event_data["historyId"])

        return last_message

    except Exception as e:
        print(f"An error occurred: {e}")
        return None


def verify_payment(user_id: str, account: str, amount: str) -> bool:
    """
    Checks if a payment is valid by verifying the user's account and amount.
    If the account ends with "9891" and the amount is 30000, it retrieves a table from a Google Spreadsheet
    and updates the status column for the user with "PAID".

    Args:
        user_id (str): The ID of the user making the payment.
        account (str): The account number associated with the payment.
        amount (str): The amount of the payment.

    Returns:
        bool: True if the payment is valid and the table in the Google Spreadsheet is updated, False otherwise.
    """
    if account.strip().endswith("9891") and int(amount) == TRANSACTION_AMOUNT:
        table = get_values(SPREADSHEET_ID, TABLE_RANGE)
        for row in table:
            if row[STUDENT_ID_COLUMN] == user_id:
                row[STATUS_COLUMN] = "PAID"
                break
        update_values(SPREADSHEET_ID, TABLE_RANGE, "RAW", table)
        print(f"Payment  for {user_id} verified!")
        return True
    return False

def check_watch_renewal() -> None:
    """
    This function checks if the duration until the expiration of the watch is less than or equal to seven days.
    If it is, the function calls the `set_watch` function to renew the watch and updates the `NEXT_WATCH` and `LAST_HISTORY_ID` variables.
    """

    global NEXT_WATCH, LAST_HISTORY_ID

    # Convert expiration time from int64 format to datetime object
    expiration_datetime = datetime.utcfromtimestamp(NEXT_WATCH) if NEXT_WATCH is not None else datetime.utcnow()

    # Calculate the duration between current time and expiration time
    time_until_expiration = expiration_datetime - datetime.utcnow()

    # Check if the duration is less than or equal to seven days
    if time_until_expiration <= timedelta(days=1):
        response = set_watch()
        NEXT_WATCH = response["expiration"]
        LAST_HISTORY_ID = response["historyId"]

def config():
    global TOPIC_NAME, SPREADSHEET_ID 

    cred = create_credentials()
    check_credentials(cred)
    check_watch_renewal()

    try:
        if SPREADSHEET_ID is None or TOPIC_NAME is None:
            SPREADSHEET_ID = os.environ.get('GOOGLE_SPREADSHEET_ID')
            TOPIC_NAME = f"projects/{os.environ.get('GOOGLE_PROJECT_ID')}/topics/{os.environ.get('GOOGLE_TOPIC_NAME')}"

    except ValueError as e:
        print(e)

def handle_notify(data):
    """
    Processes webhook data to verify credit alert payments.

    Args:
        data (dict): The webhook data containing information about the email message.

    Returns:
        Union[str, bool]: A success message if payment is verified, or a failure message if no payment is verified.
    """
    email_id = get_id(data)
    print("id", email_id)
    alert = get_credit_alert(email_id)
    
    if alert:
        payments_expected = get_pending_payments()
        reference = alert["details"].split("to")[1].lower()
        for user in payments_expected:
            if user["name"].lower() in reference or user["student id"] in reference:
                result = verify_payment(user["student id"], alert["account"], alert["amount"])
                if result:
                    return f"Payment for {user['student id']} verified!"
    
    check_watch_renewal()
    print("No payment verified!")
    return False


if __name__ == '__main__':
    pass
    
