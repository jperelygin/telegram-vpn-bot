import logging
from sqlalchemy.orm import Session
from db_models import Users, Md5Hashes, OVPNKeys


logger = logging.getLogger(__name__)


class Controller:
    def __init__(self, engine):
        self.engine = engine
        self.session = Session(bind=engine)
        self.MAX_FAIL_ATTEMPTS = 5

    def change_user_status(self, user_id, status):
        user = self.session.query(Users).filter_by(user_id=user_id).first()
        if user:
            user.status = status
            self.session.commit()
        else:
            logger.info(f"No such user with id: {user_id}.")

    def add_new_user_id(self, user_id):
        user_exists = self.session.query(Users.user_id).filter_by(user_id=user_id).first()
        if user_exists:
            logger.info(f"User {user_id} is already in db.")
            return
        new_user = Users(user_id=user_id)
        self.session.add(new_user)
        self.session.commit()
        logger.info(f"New user with user_id: {user_id} was added to db.")

    def get_user_status_by_user_id(self, user_id):
        user = self.session.query(Users.user_id).filter_by(user_id=user_id).first()
        if not user:
            logger.info(f"User with id {user_id} is not registered yet.")
            self.add_new_user_id(user_id)
        status = self.session.query(Users.status).filter_by(user_id=user_id).first()
        return status[0]

    def connect_md5_hash_with_user_id(self, user_id, md5_hash):
        status = self.get_user_status_by_user_id(user_id)
        if status == 0:
            if self.check_md5_hash(md5_hash):
                self.change_user_status(user_id, 1)
                hash_q = self.session.query(Md5Hashes).filter_by(hash=md5_hash).first()
                hash_q.user_id = user_id
                self.session.commit()
                logger.info(f"Hash {md5_hash} added to user {user_id} successfully.")
            else:
                self.increase_failed_attempts_for_user_id(user_id)
        elif status == 2:
            logger.warning(f"User {user_id} is already blocked.")
            return
        else:
            logger.warning(f"Weird, user {user_id} is authorized but trying to register MD5 hash.")

    def check_md5_hash(self, checking_hash):
        result = True
        hashes = {h[0] for h in self.session.query(Md5Hashes.hash).all()}
        already_used = self.session.query(Md5Hashes).filter_by(key=checking_hash).first().user_id is not None
        if already_used or checking_hash not in hashes:
            result = False
        return result

    def block_user_id(self, user_id):
        self.change_user_status(user_id, 2)
        logger.warning(f"User {user_id} was blocked.")

    def increase_failed_attempts_for_user_id(self, user_id):
        user = self.session.query(Users).filter_by(user_id=user_id).first()
        if not user:
            self.add_new_user_id(user_id)
            user = self.session.query(Users).filter_by(user_id=user_id).first()
        fails = user.failed_attempts + 1
        user.failed_attempts = fails
        self.session.commit()
        logger.warning(f"Failed attempts increased for user {user_id}. Current failed attempts: {fails}.")
        if fails >= self.MAX_FAIL_ATTEMPTS:
            self.block_user_id(user_id)

    def add_new_ovpn_key_to_user_id(self, ovpn_key, name, user_id):
        new_ovpn_key = OVPNKeys(user_id=user_id, key=ovpn_key, name=name)
        self.session.add(new_ovpn_key)
        self.session.commit()
        logger.info(f"New ovpn key with name {name}, location {ovpn_key} added for user {user_id}.")

    def get_all_ovpn_keys_by_user_id(self, user_id):
        return {key[0] for key in self.session.query(OVPNKeys.name).filter_by(user_id=user_id).all()}

    def get_ovpn_key_path_by_name(self, name, user_id):
        entry = self.session.query(OVPNKeys).filter_by(user_id=user_id, name=name).first()
        return entry.key
