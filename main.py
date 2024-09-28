import os.path

import hashlib

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# Gives the google sheets api client both read/write permissions
SCOPES = ['https://www.googleapis.com/auth/spreadsheets']

# MUST BE FILLED IN MANULLY
SPREADSHEET_ID = ""
API_KEY = ""
DATA_CELL_RANGE = ""
WRITE_CELL_RANGE = ""
PATH_TO_OAUTH2_TOKEN = ""
PATH_TO_GOOGLE_API_CREDENTIALS = ""

# This function will take the name and email of each individual user
# and then use a SHA-256 hashing algorithm to allow for a unique hash key identifier
# that can allow for the creation of a unique QR code for each user
def hashed_key(spreadsheet_object):
    hashed_key_values = []
    for row in spreadsheet_object["values"]:
        hasher = hashlib.sha256(b'')
        for cell in row:
            hasher.update(bytes(cell, "utf-32"))
        hasher.digest()
        hashed_key_values.append([hasher.hexdigest()])
    return hashed_key_values


# This function will retrieve the user's name and email to be used for hashing purposes
def get_name_and_email(spreadsheet_id, cell_range):
    creds = None
    # token.json stores the user's access and refresh tokens
    # automatically created after first authorization flow completion
    if os.path.exists(PATH_TO_OAUTH2_TOKEN):
        creds = Credentials.from_authorized_user_file(PATH_TO_OAUTH2_TOKEN, SCOPES)
    # If no valid credentials exist, have the user manually log in
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(PATH_TO_GOOGLE_API_CREDENTIALS, SCOPES)
            creds = flow.run_local_server(port=0)
        # Save token within the current directory for the future:
        with open("token.json", "w") as token:
            token.write(creds.to_json())

    try:
        # Create a GoogleSheets service that will be used
        service = build("sheets", "v4", developerKey=API_KEY, credentials=creds)
        # Call the Google API to read and retrieve the data from the Google Sheet:
        result = (
            service.spreadsheets()
            .values()
            .get(spreadsheetId=spreadsheet_id, range=cell_range)
            .execute()
        )
        return result
    except HttpError as error:
        print(error.error_details)
        return error


# This function will write a hashed key to the Google Forms Spreadsheet
# to be used for generating unique QR Codes for each user
def write_unique_key(spreadsheet_id, cell_range, value_input_option, _values):
    creds = None
    # token.json stores the user's access and refresh tokens
    # automatically created after first authorization flow completion
    if os.path.exists(PATH_TO_OAUTH2_TOKEN):
        creds = Credentials.from_authorized_user_file(PATH_TO_OAUTH2_TOKEN, SCOPES)
    # If no valid credentials exist, have the user manually log in
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(PATH_TO_GOOGLE_API_CREDENTIALS, SCOPES)
            creds = flow.run_local_server(port=0)
        # Save token for the future:
        with open("token.json", "w") as token:
            token.write(creds.to_json())

    try:
        # Create a GoogleSheets service that will be used
        service = build("sheets", "v4", developerKey=API_KEY, credentials=creds)
        # Create the values that will be entered within the WRITE_CELL_RANGE
        body = {"values" : _values}
        # Call the Google Sheets API to update the Google Sheet:
        result = (
            service.spreadsheets()
            .values()
            .update(
                spreadsheetId=spreadsheet_id,
                range=cell_range,
                valueInputOption=value_input_option,
                body=body
            )
            .execute()
        )
        return result
    except HttpError as err:
        print(err)


if __name__ == "__main__":
    spreadsheet_data = get_name_and_email(SPREADSHEET_ID, DATA_CELL_RANGE)
    write_unique_key(SPREADSHEET_ID, WRITE_CELL_RANGE, "RAW", hashed_key(spreadsheet_data))
