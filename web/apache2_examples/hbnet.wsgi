import sys 
sys.path.insert(0, '/var/www/html/hbnet')
#from app import hbnet_web_service as application

from app import hbnet_web_service

application = hbnet_web_service()