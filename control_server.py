import json
import requests
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
	#-------------------------------------------------------------------------------------------------
	if not authorized(update.message.chat_id):update.message.reply_text("user not authorized!");return
	#-------------------------------------------------------------------------------------------------
	update.message.reply_text("hi! I'm the bot!")
	print(context.args)	
		
def ls(update,context):
	#-------------------------------------------------------------------------------------------------
	if not authorized(update.message.chat_id):update.message.reply_text("user not authorized!");return
	#-------------------------------------------------------------------------------------------------
	if len(context.args) > 1 or len(context.args) == 0:
		update.message.reply_text("Usage: /ls <URL> , one and only one argument is required")
		return
	
	request = requests.post(context.args[0],data="ls")
	if request.status_code == 200:
		update.message.reply_text(request.text)
	else:
		update.message.reply_text("could not execute command, make sure to enter the correct URL")

def delete(update,context):
	#-------------------------------------------------------------------------------------------------
	if not authorized(update.message.chat_id):update.message.reply_text("user not authorized!");return
	#-------------------------------------------------------------------------------------------------
	if len(context.args) > 1 or len(context.args) == 0:
		update.message.reply_text("Usage: /delete <URL> , one and only one argument is required")
		return
	
	request = requests.post(context.args[0],data="delete")
	if request.status_code == 200:
		update.message.reply_text(request.text)
	else:
		update.message.reply_text("could not execute command, make sure to enter the correct URL")
		
		
if __name__ == "__main__":
	con_file = open("config.json","r")
	config = json.load(con_file)
	con_file.close()

	updater = Updater(config["http_token"])
	dispatcher = updater.dispatcher

	dispatcher.add_handler(CommandHandler("start",start))
	dispatcher.add_handler(CommandHandler("hello",hello))
	dispatcher.add_handler(CommandHandler("ls",ls))
	dispatcher.add_handler(CommandHandler("delete",delete))
	
	updater.start_polling()
	updater.idle()
