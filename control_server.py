# --------------------------------------------------------------
### CONFIGURATION ###
import json
con_file = open("config.json","r")
config = json.load(con_file)
con_file.close()
# --------------------------------------------------------------

### BOT ###
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
		
if __name__ == "__main__":
	updater = Updater(config["http_token"])
	dispatcher = updater.dispatcher

	dispatcher.add_handler(CommandHandler("start",start))
	dispatcher.add_handler(CommandHandler("hello",hello))
	
	updater.start_polling()
	updater.idle()
