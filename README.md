# VoIP Utils

Voice over IP utilities for the [voip integration](https://www.home-assistant.io/integrations/voip/).

## Test outgoing call
Install dependencies from requirements_dev.txt

Set environment variables for source and destination endpoints in .env file
    CALL_SRC_USER = "homeassistant"
    CALL_SRC_IP = "192.168.1.1"
    CALL_SRC_PORT = 5060
    CALL_VIA_IP = "192.168.1.1"
    CALL_DEST_IP = "192.168.1.2"
    CALL_DEST_PORT = 5060
    CALL_DEST_USER = "phone"

Run script
python call_example.py

