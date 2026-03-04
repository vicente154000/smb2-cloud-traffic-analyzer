import os
import time
import threading
import shutil
import ntplib
from datetime import datetime, timezone
from pysharkUtils import PysharkUtils
from sftpTransfer import SFTP
import asyncio

class SyncedClock:
	def __init__(self, ntp_server='pool.ntp.org'):
		self.ntp_server = ntp_server
		self.client = ntplib.NTPClient()
	
	def now(self):
		try:
			response = self.client.request(self.ntp_server, version=3)
			return datetime.fromtimestamp(response.tx_time, tz=timezone.utc)
		except Exception as e:
			print(f"Error syncing with NTP: {e}")
			return datetime.now(timezone.utc)

class Operations:
	
	def __init__(self, sftp):
		self.sftp = sftp


	# Create a file with random data of the specified size:
	@staticmethod
	def create_random_data(size_in_bytes):
		return os.urandom(size_in_bytes)
	
	@staticmethod
	def create_folder(base_path, folder_name):
		full_path = os.path.join(base_path, folder_name)		
		os.makedirs(full_path, exist_ok=True)

	@staticmethod
	def upload(base_path, file_name, data):
		full_path = os.path.join(base_path, file_name)
		#os.makedirs(full_path, exist_ok=True)
		with open(full_path, "wb") as f:
			f.write(data)

	@staticmethod
	def copy(base_path, source_path, destination_path):
		full_path_src = os.path.join(base_path, source_path)
		full_path_dst = os.path.join(base_path, destination_path)
		shutil.copy2(full_path_src, full_path_dst)

	@staticmethod
	def zip(base_path, folder_name, destination_path):
		full_path_src = os.path.join(base_path, folder_name)
		full_path_dst = os.path.join(base_path, destination_path)
		return shutil.make_archive(full_path_dst, 'zip', full_path_src)
		#return shutil.make_archive(full_path_dst, 'gztar', full_path_src)

	@staticmethod
	def move(base_path, source_file, destination_path):
		full_path_src = os.path.join(base_path, source_file)
		full_path_dst = os.path.join(base_path, destination_path, source_file)
		os.rename(full_path_src, full_path_dst)

	@staticmethod
	def delete(base_path, folder_name): 
		full_path = os.path.join(base_path, folder_name)
		Operations.deletePath(full_path)

	@staticmethod
	def deletePath(full_path): 
		if os.path.isfile(full_path):
			os.remove(full_path)
		elif os.path.isdir(full_path):
			shutil.rmtree(full_path)
		else:
			print("Unknown directory/file type")
	

	async def runAll(self, dropbox_path:str, remote_dropbox_path:str):
			
		
		access_token = self.sftp.get_token()

		# A.0.- Create folder:
		pktCapture = PysharkUtils(interface='enp2s0', timeout=None, bpf_filter=None)
	
		# Monitor all operations in one file:
		output_file=f'../data/capture_ALL.pcap'
		full_thread, full_stop_event = pktCapture.capture_async(output_file)

		# Monitor network without operation: 
		print("OP: No Operation")
		action = "NO_OPERATION"
		output_file=f'../data/capture_{action}.pcap'
		thread, stop_event = pktCapture.capture_async(output_file)
		time.sleep(5)
		await PysharkUtils.stop(thread, stop_event)
		print("Action timeout:", clock.now())


		moved_folder = "moved"
		print("OP: Created folder : ", moved_folder)
		action = "CREATE_FOLDER"
		output_file=f'../data/capture_{action}.pcap'
		thread, stop_event = pktCapture.capture_async(output_file)
		self.create_folder(dropbox_path, moved_folder)
		time.sleep(2)
		await PysharkUtils.stop(thread, stop_event)
		print("Action timeout:", clock.now())

		# Upload files of different sizes:
		file_sizes = [1, 50] #, 200]
		for size in file_sizes:
			file_name = f"file_{size}MB.bin"  # Dropbox destination path (must start with '/')  
			
			print("Operations start for size: ", size)			
			
			# A.1.- Upload file:
			print("OP: File upload : ", file_name)
			action = "UPLOAD"
			output_file=f'../data/capture_{action}_{size}MB.pcap'
			thread, stop_event = pktCapture.capture_async(output_file)
			print(f"Active threads: {threading.active_count()}")
			data  = self.create_random_data(size * 1024 * 1024)
			self.upload(dropbox_path, file_name, data)
			time.sleep(4 + 0.1 * size)	# Increase timeout according to the file size.
			await PysharkUtils.stop(thread, stop_event)
			print(f"Active threads: {threading.active_count()}")
			print("Action timeout:", clock.now())
						
			# A.2.- Download file:
			print("OP: File download: ", f"remote_{file_name}")
			action = "DOWNLOAD"
			output_file=f'../data/capture_{action}_{size}MB.pcap'
			thread, stop_event = pktCapture.capture_async(output_file)
			print(f"Active threads: {threading.active_count()}")
			
			remote_file_name = f"remote_{file_name}"
			#remote_data  = self.create_random_data(size * 1024 * 1024)
			#full_remote_path = os.path.join(remote_dropbox_path, remote_file_name)
			#self.upload(current_path, file_name, remote_data)
			self.sftp.transfer_file(access_token, None, None, size)
			time.sleep(5 + 0.2 * size)	# Wait for upload and download
			await PysharkUtils.stop(thread, stop_event)
			print(f"Active threads: {threading.active_count()}")
			print("Action timeout:", clock.now())
			
			# self.download(dropbox_path)
			# print("OP: File download : ", dropbox_path)
			# time.sleep(2)
			# print("Action timeout:", clock.now())

			# A.3.- Copy file:
			copy_dropbox_name = file_name + "_2"
			print("OP: Copy File to : ", copy_dropbox_name)
			action = "COPY"
			output_file=f'../data/capture_{action}_{size}MB.pcap'
			thread, stop_event = pktCapture.capture_async(output_file)
			self.copy(dropbox_path, file_name, copy_dropbox_name)
			time.sleep(2)
			await PysharkUtils.stop(thread, stop_event)
			print("Action timeout:", clock.now())
			
			# A.4.- Move file:
			#mv_file_path = moved_folder + dropbox_path
			print("OP: Move File to : ", copy_dropbox_name)
			action = "MOVE"
			output_file=f'../data/capture_{action}_{size}MB.pcap'
			thread, stop_event = pktCapture.capture_async(output_file)
			self.move(dropbox_path, copy_dropbox_name, moved_folder)
			time.sleep(2)
			await PysharkUtils.stop(thread, stop_event)
			print("Action timeout:", clock.now())

			# A.X.- ZIP OPERATION!!!
			print("OP: Compress Folder to : ", copy_dropbox_name + ".tar")
			compressed_folder_name = moved_folder
			action = "TAR"
			output_file=f'../data/capture_{action}_{size}MB.pcap'
			thread, stop_event = pktCapture.capture_async(output_file)
			compressed_file_path = self.zip(dropbox_path, moved_folder, compressed_folder_name)
			time.sleep(2)
			await PysharkUtils.stop(thread, stop_event)
			print("Action timeout:", clock.now())

			# A.5.- Delete file:
			print("OP: Delete Files: ", dropbox_path)
			action = "DELETE_FILES"
			output_file=f'../data/capture_{action}_{size}MB.pcap'
			thread, stop_event = pktCapture.capture_async(output_file)
			self.delete(dropbox_path, file_name)
			time.sleep(2)
			self.deletePath(compressed_file_path)
			time.sleep(2)
			self.delete(dropbox_path, remote_file_name)
			time.sleep(2)
			await PysharkUtils.stop(thread, stop_event)
			print("Action timeout:", clock.now())
			

		# B.- Delete folder:
		print("OP: Delete folder : ", moved_folder)
		action = "DELETE_FOLDER"
		output_file=f'../data/capture_{action}.pcap'
		thread, stop_event = pktCapture.capture_async(output_file)
		self.delete(dropbox_path, moved_folder)
		time.sleep(2)
		await PysharkUtils.stop(thread, stop_event)
		print("Action timeout:", clock.now())

		await PysharkUtils.stop(full_thread, full_stop_event)



# Example usage:
if __name__ == "__main__":

	# Get synced clock:
	clock = SyncedClock()
	dropbox_path = "/home/aeguzkiza/Dropbox/Apps/TLM_25"
	remote_dropbox_path = "/home/admin/Dropbox/Apps/TLM_25/"

	
	hostname = "10.6.27.121"
	port = 22
	username = "rsng"
	password = "rsng_access"
	dropbox_token = "61cw68vin2ax05z"
	script_location = "/home/rsng/Dropbox"

	sftp = SFTP(hostname, port, username, password, dropbox_token, script_location)
	client = Operations(sftp)

	asyncio.run(client.runAll(dropbox_path, remote_dropbox_path))










