import os
import logging

from sqlalchemy import create_engine

from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes, CallbackContext, MessageHandler, filters

import db_models
from db_controller import Controller
from credentials import Credentials
from ovpn_key_generator import generate_ovpn_key_locally


credentials = Credentials()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(credentials.get("LOGFILE"))
    ]
)
logging.getLogger("httpx").setLevel(logging.WARNING)
logger = logging.getLogger(__name__)

engine = create_engine(f"sqlite:///{credentials.get('DATABASE')}")
db_models.create_tables(engine)
controller = Controller(engine=engine)


async def unknown_message(update: Update, context: CallbackContext):
    await update.message.reply_text(credentials.get("WRONG_COMMAND"))


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if controller.get_user_status_by_user_id(user_id) == 2:
        await update.message.reply_text(credentials.get("BLOCKED"))
        return
    await update.message.reply_text(credentials.get("START"))


async def register(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if controller.get_user_status_by_user_id(user_id) == 2:
        await update.message.reply_text(credentials.get("BLOCKED"))
        return
    try:
        hash_key = context.args[0]
        if controller.check_md5_hash(hash_key):
            controller.connect_md5_hash_with_user_id(user_id=user_id, md5_hash=hash_key)
            await update.message.reply_text(credentials.get("REGISTER_SUCCESS"))
        else:
            await update.message.reply_text(credentials.get("REGISTER_NO_MD5"))
    except (IndexError, ValueError):
        await update.message.reply_text(credentials.get("BAD_COMMAND_USAGE"))


async def help_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(credentials.get("HELP"))


async def generate_ovpn_key(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    status = controller.get_user_status_by_user_id(user_id)
    if status == 2:
        await update.message.reply_text(credentials.get("BLOCKED"))
        return
    elif status == 0:
        await update.message.reply_text(credentials.get("REGISTER_NOT_COMPLETED_YET"))
        return
    try:
        name = context.args[0]
        list_of_keys = controller.get_all_ovpn_keys_by_user_id(user_id)
        if name in list_of_keys:
            await update.message.reply_text(credentials.get("KEY_NAME_NOT_UNIQUE"))
            return
        path_to_file = generate_ovpn_key_locally(name)
        chat_id = update.message.chat_id

        controller.add_new_ovpn_key_to_user_id(ovpn_key=path_to_file, name=name, user_id=user_id)

        if not os.path.exists(path_to_file):
            raise FileNotFoundError(f"The file {path_to_file} does not exist!")

        with open(path_to_file, "rb") as f:
            await context.bot.send_document(chat_id=chat_id, document=f)
        await update.message.reply_text(credentials.get("KEY_GENERATED"))
    except (IndexError, ValueError):
        await update.message.reply_text(credentials.get("BAD_COMMAND_USAGE"))


async def list_ovpn_keys(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    status = controller.get_user_status_by_user_id(user_id)
    if status == 2:
        await update.message.reply_text(credentials.get("BLOCKED"))
        return
    elif status == 0:
        await update.message.reply_text(credentials.get("REGISTER_NOT_COMPLETED_YET"))
        return
    list_of_keys = controller.get_all_ovpn_keys_by_user_id(user_id)
    await update.message.reply_text("\n".join(f"{i}" for i in list_of_keys))


async def send_ovpn_key(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    chat_id = update.message.chat_id
    name = context.args[0]
    if name in controller.get_all_ovpn_keys_by_user_id(user_id):
        path_to_file = controller.get_ovpn_key_path_by_name(name, user_id)
        if not os.path.exists(path_to_file):
            raise FileNotFoundError(f"The file {path_to_file} does not exist!")
        with open(path_to_file, "rb") as f:
            await context.bot.send_document(chat_id=chat_id, document=f)
    else:
        await update.message.reply_text(credentials.get("NO_SUCH_OVPN_KEY"))


async def error_handler(update: object, context: ContextTypes.DEFAULT_TYPE):
    logger.error(context.error)
    if isinstance(update, Update) and update.message:
        logger.error(f"Error accured while working with user: {update.effective_user.id} {update.effective_user.username}")
        await update.message.reply_text(credentials.get("ERROR"))


def main():
    application = Application.builder().token(credentials.get("APIKEY")).build()

    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("help", help_message))
    application.add_handler(CommandHandler("register", register, has_args=1))
    application.add_handler(CommandHandler("new_key", generate_ovpn_key, has_args=1))
    application.add_handler(CommandHandler("key_list", list_ovpn_keys))
    application.add_handler(CommandHandler("get_key", send_ovpn_key, has_args=1))

    application.add_handler(MessageHandler(filters.COMMAND, unknown_message))

    application.add_error_handler(error_handler)

    application.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
