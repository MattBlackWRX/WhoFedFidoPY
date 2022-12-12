import base64

from email.message import EmailMessage
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from google.oauth2.credentials import Credentials

SCOPES = ['https://www.googleapis.com/auth/gmail.send']


def gmail_send_message():
    """Create and send an email message
    Print the returned  message id
    Returns: Message object, including message id

    Load pre-authorized user credentials from the environment.
    See https://developers.google.com/identity
    for guides on implementing OAuth2 for the application.
    """
    creds = Credentials.from_authorized_user_file('token.json', SCOPES)

    try:
        service = build('gmail', 'v1', credentials=creds)
        message = EmailMessage()

        message.set_content('Archer has been fed!')

        message['To'] = 'mclarenmanmatt@gmail.com'
        message['From'] = 'mclarenmanmatt@gmail.com'
        message['Subject'] = 'Archer has been fed!'

        # encoded message
        encoded_message = base64.urlsafe_b64encode(message.as_bytes()) \
            .decode()

        create_message = {
            'raw': encoded_message
        }
        # pylint: disable=E1101
        send_message = (service.users().messages().send
                        (userId="me", body=create_message).execute())
        print(F'Message Id: {send_message["id"]}')
    except HttpError as error:
        print(F'An error occurred: {error}')
        send_message = None
    return send_message


if __name__ == '__main__':
    gmail_send_message()