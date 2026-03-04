import paramiko
import os
import time
import re
import threading

class SFTP:

    def __init__(self, hostname: str, port:int, username: str, password: str, dropbox_token: str, scriptLocation: str):
        self.hostname = hostname
        self.port = port
        self.username = username
        self.password = password
        self.dropbox_token = dropbox_token
        self.scriptLocation = scriptLocation
    
    @staticmethod
    def sendFile(ssh, file_data, remote_path):  
        # Open SFTP session
        sftp = ssh.open_sftp()

        # Create remote directory if it doesn't exist
        remote_dir = os.path.dirname(remote_path)
        try:
            sftp.listdir(remote_dir)
        except IOError:
            # Directory doesn't exist
            sftp.mkdir(remote_dir)

        # Upload file
        with sftp.open(remote_path, "wb") as remote_file:
            remote_file.write(file_data)

        #sftp.put(local_path, remote_path)

        # Close connections
        sftp.close()


    def connectSSH(self):
        """
        Connects to remote server using SSH
        """

        # Create SSH client
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        # Connect to remote server
        ssh.connect(self.hostname, port=self.port, username=self.username, password=self.password)
        return ssh
    

    
    def get_token(self):
              
        # Create SSH client
        ssh = self.connectSSH()
        access_token = self._get_token(ssh, self.dropbox_token, self.scriptLocation)

        ssh.close()

        print("File transferred successfully.")

        return access_token


    @staticmethod
    def _get_token(ssh, dropbox_token: str, scriptLocation: str):

        channel = ssh.invoke_shell(term='xterm')        
        output = SFTP.readChannel(channel)
        print("OUTPUT:", output)

        channel.send(f"bash\n")

        output = SFTP.readChannel(channel)
        print("OUTPUT:", output)

        channel.send(f"cd {scriptLocation}\n")
        output = SFTP.readChannel(channel)
        print("OUTPUT:", output)

        channel.send(f"source dropbox/bin/activate\n")
        output = SFTP.readChannel(channel)
        print("OUTPUT:", output)

        channel.send(f"./dropbox/bin/python3 dropboxToken.py {dropbox_token}\n")
        output = SFTP.readChannel(channel)

        buffer = ""    
        while True:
            output = SFTP.readChannel(channel)
            buffer += output
            print(output, end="")
            if "Enter the authorization code here: " in buffer:
                break

        SFTP.addCode(channel)
        #time.sleep(0.2)
        #output = channel.recv(9999).decode()
        output = SFTP.readChannel(channel)
        
        # Isolate the token from the whole text:
        access_token = output.split("Access token:", 1)[1].split("\r\n", 1)[0].strip()
        #print("OUTPUT:", output)
        return access_token


    def transfer_file(self, access_token: str, file_data, remote_path: str, file_size: int):
        
        # Ensure the local file exists
        #if not file_data:
        #   raise FileNotFoundError(f"File data not found to save on: {remote_path}")

        # Create SSH client
        ssh = self.connectSSH()

        #self.sendFile(file_data, remote_path)
        self.runFileUploader(ssh, access_token, file_size)

        ssh.close()

        print("File transferred successfully.")


    def runFileUploader(self, ssh, access_token: str, file_size: int):
        
        channel = ssh.invoke_shell(term='xterm')        
        output = SFTP.readChannel(channel)
        print("OUTPUT:", output)

        channel.send(f"bash\n")
        #time.sleep(0.5)
        #output = channel.recv(9999).decode()
        output = SFTP.readChannel(channel)
        print("OUTPUT:", output)

        channel.send(f"cd {self.scriptLocation}\n")
        output = SFTP.readChannel(channel)
        print("OUTPUT:", output)

        channel.send(f"source dropbox/bin/activate\n")
        output = SFTP.readChannel(channel)
        print("OUTPUT:", output)

        destination_path = "/"
        channel.send(f"./dropbox/bin/python3 uploadFile.py {access_token} {destination_path} {file_size}\n")        
        # Read output until script asks for input
        
        output = SFTP.readChannel(channel)
        time.sleep(5)
        print("OUTPUT:", output)

        # Example: python3 uploadFile.py token / 1
        #commands = (
        #    f"cd {self.scriptLocation} && "
        #    #f". dropbox/bin/activate && "
        #    #f"bash -c 'source dropbox/bin/activate && "
        #    f"./dropbox/bin/python3 uploadFile.py {self.dropbox_token} / {file_size}"
        #)
        #print("COMMAND SENT:", commands)

        #stdin, stdout, stderr = ssh.exec_command(commands)
        #print(stdin.read().decode())
        #print(stdout.read().decode())
        #print(stderr.read().decode())

    @staticmethod
    def showChannel(channel):
        SFTP.readChannel(channel)
        print("OUTPUT:", output)


    @staticmethod
    def readChannel(channel):
        """
        Docstring for readChannel
        
        :param channel: SSH channel.

        We wait until terminal is ready to show info.
        """
        while not channel.recv_ready():
            time.sleep(0.1)

        output = ""
        while channel.recv_ready():
            chunk = channel.recv(4096).decode()
            output += chunk
            time.sleep(0.1)  # Small delay to let more data arrive                

        return output


    @staticmethod
    def fetchUrl(text: str):
        match = re.search(r"Go to:\s*(https?://\S+)", text)
        if match:
            url = match.group(1)
            return url
        else:
            print("URL not found!")

    @staticmethod
    def addCode(channel):
        try:
            #while True:
            auth_code = auth_code = input()
            auth_code = auth_code.replace("\x1b[200~", "").replace("\x1b[201~", "").strip()
            channel.send(auth_code + "\n")  # Send to remote shell
            time.sleep(2)
            #print(f"Auth code sent: {auth_code}")            
        except KeyboardInterrupt:
            print("Exiting interactive session...")
            channel.close()


    


# Example usage:
if __name__ == "__main__":

    """
    # Example usage
    SFTP(
        hostname="your.server.com",
        port=22,
        username="your_user",
        password="your_password",
        local_path="/path/to/local/file.txt",
        remote_path="/remote/target/folder/file.txt"
        dropbox_token="api_token"
        script_location="/path/to/script.py"
    )
    """


    dropbox_path = "/home/aeguzkiza/Dropbox/Apps/TLM_25"
    remote_dropbox_path = "/home/admin/Dropbox/Apps/TLM_25/"
    
    hostname = "10.6.27.121"
    port = 22
    username = "rsng"
    password = "rsng_access"
    dropbox_token = "61cw68vin2ax05z"
    script_location = "/home/rsng/Dropbox"

    sftp = SFTP(hostname, port, username, password, dropbox_token, script_location)
    access_token = sftp.get_token()
    sftp.transfer_file(access_token=access_token, file_data=None, remote_path=None, file_size=1)

