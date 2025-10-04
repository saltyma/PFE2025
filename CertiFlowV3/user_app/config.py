# user_app/config.py

# --- Central Configuration for the User Application ---

# This is the network address of the CA Owner's API server.
# The User App will send all registration and status requests to this URL.

# IMPORTANT: You must replace "0.0.0.0" with the actual local IP address
# of the Raspberry Pi that will be running the `ca_app/api_server.py`.
#
# To find the IP address, run the command `hostname -I` in the terminal
# on your Raspberry Pi.

CA_API_URL = "http://127.0.0.1:7001" 
