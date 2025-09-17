import os

class Env:
    GOOGLE_APPLICATION_CREDENTIALS: str
    SESH_PRO_BACKEND_UNSAFE_LOGGING = False
    SESH_PRO_BACKEND_UNSAFE_LOGGING_VERBOSE = False
    def __init__(self):
        self.GOOGLE_APPLICATION_CREDENTIALS = os.getenv('GOOGLE_APPLICATION_CREDENTIALS')

        if not self.GOOGLE_APPLICATION_CREDENTIALS:
            raise ValueError("GOOGLE_APPLICATION_CREDENTIALS environment variable not set")

        if not os.path.exists(self.GOOGLE_APPLICATION_CREDENTIALS):
            raise FileNotFoundError(f"Service account file not found: {self.GOOGLE_APPLICATION_CREDENTIALS}")

        unsafe_logging = os.getenv('SESH_PRO_BACKEND_UNSAFE_LOGGING')
        if unsafe_logging == '1':
            self.SESH_PRO_BACKEND_UNSAFE_LOGGING = True
            print("SESH_PRO_BACKEND_UNSAFE_LOGGING environment is set, this must not be used in production!")


env: None | Env = None
