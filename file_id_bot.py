from telegram.ext import Updater, MessageHandler, Filters

# ===========================
# YOUR BOT TOKEN
# ===========================
BOT_TOKEN = "8259780372:AAHwTmuhkr6eugiMsLVqTAqNnkCu5Ljddo4"

# ===========================
# WHEN USER SENDS A VIDEO
# ===========================
def save_video(update, context):
    file_id = update.message.video.file_id
    update.message.reply_text(f"📌 Your Video File ID:\n\n`{file_id}`", parse_mode="Markdown")


# ===========================
# START BOT
# ===========================
updater = Updater(BOT_TOKEN, use_context=True)
dp = updater.dispatcher

dp.add_handler(MessageHandler(Filters.video, save_video))

updater.start_polling()
updater.idle()