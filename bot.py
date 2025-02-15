import os
import logging

from sqlalchemy import create_engine

import db_models
from db_controller import Controller
from credentials import Credentials

from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes, CallbackContext, MessageHandler, filters


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
        # TODO: Remove
        logger.info(f"Chat id: {chat_id}")

        controller.add_new_ovpn_key_to_user_id(ovpn_key=path_to_file, name=name, user_id=user_id)

        if not os.path.exists(path_to_file):
            raise FileNotFoundError(f"The file {path_to_file} does not exist!")

        with open(path_to_file, "rb") as f:
            context.bot.send_document(chat_id=chat_id, document=f)
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


async def error_handler(update: object, context: ContextTypes.DEFAULT_TYPE):
    logger.error(context.error)
    if isinstance(update, Update) and update.message:
        logger.error(f"Error accured while working with user: {update.effective_user.id} {update.effective_user.username}")
        await update.message.reply_text(credentials.get("ERROR"))


def generate_ovpn_key_locally(name):
    os.system(f'cd /{credentials.get("OPENVPN_SERVER_PATH")}/easy-rsa '
              f'&& ./easyrsa --batch --days=3650 build-client-full "{name}" nopass')
    output_file = f'{credentials.get("OPENVPN_KEYS_FOLDER")}/{name}.ovpn'

    base_config_path = f"{credentials.get('OPENVPN_SERVER_PATH')}/server.conf"
    ca_cert_path = f"{credentials.get('OPENVPN_SERVER_PATH')}/easy-rsa/pki/ca.crt"
    client_cert_path = f"{credentials.get('OPENVPN_SERVER_PATH')}/easy-rsa/pki/issued/{name}.crt"
    client_key_path = f"{credentials.get('OPENVPN_SERVER_PATH')}/easy-rsa/pki/private/{name}.key"
    tls_auth_key_path = f"{credentials.get('OPENVPN_SERVER_PATH')}/tc.key"

    with open(output_file, "w") as ovpn_file:
        with open(base_config_path, "r") as base_config:
            ovpn_file.write(base_config.read())

        ovpn_file.write("\n<ca>\n")
        with open(ca_cert_path, "r") as ca_cert:
            ovpn_file.write(ca_cert.read())
        ovpn_file.write("</ca>\n")

        ovpn_file.write("\n<cert>\n")
        with open(client_cert_path, "r") as client_cert:
            ovpn_file.write(client_cert.read())
        ovpn_file.write("</cert>\n")

        ovpn_file.write("\n<key>\n")
        with open(client_key_path, "r") as client_key:
            ovpn_file.write(client_key.read())
        ovpn_file.write("</key>\n")

        ovpn_file.write("\n<tls-crypt>\n")
        with open(tls_auth_key_path, "r") as tls_crypt_key:
            ovpn_file.write(tls_crypt_key.read())
        ovpn_file.write("</tls-crypt>\n")

    logger.info(f"New {output_file} file generated.")
    return output_file


def main():
    application = Application.builder().token(credentials.get("APIKEY")).build()

    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("help", help_message))
    application.add_handler(CommandHandler("register", register, has_args=1))
    application.add_handler(CommandHandler("new_key", generate_ovpn_key, has_args=1))
    application.add_handler(CommandHandler("key_list", list_ovpn_keys))

    application.add_handler(MessageHandler(filters.COMMAND, unknown_message))

    application.add_error_handler(error_handler)

    application.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
