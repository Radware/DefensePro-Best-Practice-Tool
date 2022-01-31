import getpass
from vision import *

if __name__ == "__main__":

 Vision_IP = input("Enter Vision IP: ")
 Vision_user = input("Enter Vision User: ")
 Vision_password = getpass.getpass("Enter Vision Password: ") 
 try:
 	vision_obj = Vision(Vision_IP, Vision_user, Vision_password)
 except FileNotFoundError:
 	print(f"Error: Config File is not Found")
 	exit(1) 
 DefensePro_list = vision_obj.config_file.get_dp_list()
 BP_Tool_run(vision_obj,DefensePro_list)
