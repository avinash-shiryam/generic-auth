"""
Contains class and methods for user authenticattion and DB interactions.
"""
import datetime
import json
import logging as log
import os

import jwt
from pytz import timezone
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy_json import mutable_json_type

from Engine import bcrypt, db
from Engine.models.generic import base


class User(base.Base):
    """
    Class def for user DB
    """

    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_sub = db.Column(db.String())
    user_type = db.Column(db.String())
    country = db.Column(db.String())
    email_id = db.Column(db.String(254))
    isd_code = db.Column(db.String())
    phone_number = db.Column(db.String())
    name = db.Column(db.String())
    password = db.Column(db.String(100))
    state = db.Column(db.String())
    industry_domain = db.Column(db.String())
    status = db.Column(db.String())
    basic_info_json = db.Column(db.String())
    business_info_json = db.Column(db.String())
    personal_info_json = db.Column(db.String())
    authorisers_info_json = db.Column(db.String())
    documents_json = db.Column(db.String())
    permissions = db.Column(db.String())
    total_accounts = db.Column(db.Integer)
    active_accounts = db.Column(db.Integer)
    total_balance = db.Column(db.Float)
    collections = db.Column(db.ARRAY(db.String()))
    meta_data = db.Column(db.String())
    last_accessed = db.Column(db.DateTime)
    activate_on = db.Column(db.DateTime)
    pending_payments = db.Column(db.Float)
    client_id = db.Column(db.String())
    client_key = db.Column(db.String())
    client_secret_key = db.Column(db.String())
    priority_status = db.Column(db.String())
    transaction_count = db.Column(db.Float)
    transaction_value = db.Column(db.Float)
    average_transaction = db.Column(db.Float)
    onboard_data = db.Column(mutable_json_type(dbtype=JSONB, nested=True))
    partner_name = db.Column(db.String())
    last_transaction_date = db.Column(db.DateTime)
    index_save = False

    def __init__(self, data_dict=None, id=None):
        if data_dict is None:
            data_dict = {}
        self.id = id or data_dict.get("id")
        self.user_type = data_dict.get("user_type")
        self.user_sub = data_dict.get("user_sub")
        self.country = data_dict.get("country")
        self.email_id = data_dict.get("email_id")
        self.isd_code = data_dict.get("isd_code")
        self.phone_number = data_dict.get("phone_number")
        self.name = data_dict.get("name")
        if data_dict.get("password"):
            self.password = bcrypt.generate_password_hash(
                data_dict.get("password")
            ).decode()
        self.state = data_dict.get("state", "")
        self.industry_domain = data_dict.get("industry_domain")
        self.status = data_dict.get("status", "inactive")
        self.basic_info_json = json.dumps(data_dict.get("basic_info_json", {}))
        self.business_info_json = json.dumps(data_dict.get("business_info_json", {}))
        self.personal_info_json = json.dumps(data_dict.get("personal_info_json", {}))
        self.authorisers_info_json = json.dumps(
            data_dict.get("authorisers_info_json", {})
        )
        self.documents_json = json.dumps(data_dict.get("documents_json", {}))
        self.permissions = data_dict.get("permissions", [])
        self.total_accounts = data_dict.get("total_accounts", 0)
        self.active_accounts = data_dict.get("active_accounts", 0)
        self.total_balance = data_dict.get("total_balance", 0)
        self.collections = data_dict.get("collections")
        self.meta_data = json.dumps(data_dict.get("meta_data", {}))
        self.last_accessed = datetime.datetime.now()
        self.pending_payments = data_dict.get("pending_payments")
        self.client_id = data_dict.get("client_id")
        self.client_key = data_dict.get("client_key")
        self.client_secret_key = data_dict.get("client_secret_key")
        self.priority_status = data_dict.get("priority_status", "P5")
        self.transaction_count = data_dict.get("transaction_count", 0)
        self.transaction_value = data_dict.get("transaction_value", 0.0)
        self.average_transaction = data_dict.get("average_transaction", 0.0)
        self.onboard_data = (
            data_dict.get("onboard_data") if data_dict.get("onboard_data") else {}
        )
        self.partner_name = (
            data_dict.get("partner_name")
            if data_dict.get("partner_name")
            else "pending"
        )
        self.last_transaction_date = data_dict.get("last_transaction_date")
        super().__init__(
            self.created_at, self.updated_at, self.group_id, self.deleted_at
        )

    def delete(self):
        """
        Sets status of object as False in DB
        """
        self.last_accessed = datetime.datetime.now()
        self.deleted_at = datetime.datetime.now()
        db.session.query(self.__class__).filter(self.__class__.id == self.id).update(
            {"last_accessed": self.last_accessed, "deleted_at": self.deleted_at}
        )
        db.session.commit()

    def to_db_storable_dict(self, skip_list):
        """
        Creates a dict for saving object to DB.
        """
        resp_dict = {
            "id": self.id,
            "user_type": self.user_type,
            "user_sub": self.user_sub,
            "country": self.country,
            "email_id": self.email_id,
            "isd_code": self.isd_code,
            "phone_number": self.phone_number,
            "name": self.name,
            "password": self.password,
            "state": self.state,
            "industry_domain": self.industry_domain,
            "status": self.status,
            "basic_info_json": self.basic_info_json,
            "business_info_json": self.business_info_json,
            "personal_info_json": self.personal_info_json,
            "authorisers_info_json": self.authorisers_info_json,
            "documents_json": self.documents_json,
            "permissions": self.permissions,
            "total_accounts": self.total_accounts,
            "active_accounts": self.active_accounts,
            "total_balance": self.total_balance,
            "collections": self.collections,
            "meta_data": self.meta_data,
            "last_accessed": self.last_accessed,
            "activate_on": self.activate_on,
            "pending_payments": self.pending_payments,
            "client_id": self.client_id,
            "client_key": self.client_key,
            "client_secret_key": self.client_secret_key,
            "deleted_at": self.deleted_at,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "last_transaction_date": self.last_transaction_date,
        }
        [resp_dict.pop(x, None) for x in skip_list]
        return resp_dict

    def to_response_dict(self, skip_list=[]):
        """
        Creates a dict for sending a response to user.
        """
        resp_dict = {
            "id": self.id,
            "user_type": self.user_type,
            "user_sub": self.user_sub,
            "country": self.country,
            "email_id": self.email_id,
            "isd_code": self.isd_code,
            "phone_number": self.phone_number,
            "name": self.name,
            "state": self.state,
            "industry_domain": self.industry_domain,
            "status": self.status,
            "basic_info_json": json.loads(self.basic_info_json)
            if self.basic_info_json
            else None,
            "business_info_json": json.loads(self.business_info_json)
            if self.business_info_json
            else None,
            "personal_info_json": json.loads(self.personal_info_json)
            if self.personal_info_json
            else None,
            "authorisers_info_json": json.loads(self.authorisers_info_json)
            if self.authorisers_info_json
            else None,
            "documents_json": json.loads(self.documents_json)
            if self.documents_json
            else None,
            "permissions": self.permissions,
            "total_accounts": self.total_accounts,
            "active_accounts": self.active_accounts,
            "total_balance": self.total_balance,
            "collections": self.collections,
            "meta_data": json.loads(self.meta_data) if self.meta_data else None,
            "updated_at": self.updated_at.astimezone(timezone("Asia/Kolkata")).strftime(
                "%Y-%m-%d %H:%M:%S"
            )
            if self.updated_at
            else None,
            "last_accessed": self.last_accessed.astimezone(
                timezone("Asia/Kolkata")
            ).strftime("%Y-%m-%d %H:%M:%S")
            if self.last_accessed
            else None,
            "activate_on": self.activate_on,
            "pending_payments": self.pending_payments,
            "client_id": self.client_id,
            "client_key": self.client_key,
            "client_secret_key": self.client_secret_key,
            "priority_status": self.priority_status,
            "transaction_count": self.transaction_count
            if self.transaction_count
            else 0,
            "transaction_value": self.transaction_value
            if self.transaction_value
            else 0.0,
            "average_transaction": self.average_transaction
            if self.average_transaction
            else 0.0,
            "partner_name": self.partner_name,
            "registered_on": self.created_at.astimezone(
                timezone("Asia/Kolkata")
            ).strftime("%Y-%m-%d %H:%M:%S")
            if self.created_at
            else None,
            "last_transaction_date": self.last_transaction_date.astimezone(
                timezone("Asia/Kolkata")
            ).strftime("%Y-%m-%d %H:%M:%S")
            if self.last_transaction_date
            else None,
            "deleted_at": self.deleted_at.astimezone(timezone("Asia/Kolkata")).strftime(
                "%Y-%m-%d %H:%M:%S"
            )
            if self.deleted_at
            else None,
            "onboard_data": self.onboard_data if self.onboard_data else {},
        }
        [resp_dict.pop(x, None) for x in skip_list]
        return resp_dict

    def update_login(self):
        """
        Update last accessed whenever user logging in
        """
        self.last_accessed = datetime.datetime.now()
        db.session.query(self.__class__).filter(self.__class__.id == self.id).update(
            {"last_accessed": self.last_accessed}
        )
        db.session.commit()

    @staticmethod
    def generate_auth_token(email_id):
        """
        Generates the Auth Token
        """
        try:
            payload = {
                "exp": datetime.datetime.utcnow()
                + datetime.timedelta(days=2, seconds=0),
                "iat": datetime.datetime.utcnow(),
                "sub": email_id,
            }
            return jwt.encode(payload, os.getenv("SECRET_KEY"), algorithm="HS256")
        except Exception as e:
            log.error(e)

    def __repr__(self):
        return "<User {}>".format(self.id)

    @staticmethod
    def fetch_by_id(params):
        """
        Fetches data from DB by id.
        """
        try:
            params["deleted_at"] = None
            data_object = db.session.query(User).filter_by(**params).first()
            if data_object:
                return data_object
        except Exception as e:
            log.error(e, exc_info=True)
            return False

    @staticmethod
    def find_by_email(email_id):
        """
        Returns user object from DB using email_id
        """
        try:
            user_obj = User.query.filter_by(email_id=email_id, deleted_at=None).first()
            if user_obj and user_obj.deleted_at is None:
                return user_obj
            return False
        except Exception as e:
            log.error(e, exc_info=True)
            return False

    @staticmethod
    def fetch_by_provided_data(params):
        """
        Fetches data from DB by provided data.
        """
        try:
            params["deleted_at"] = None
            user_object = User.query.filter_by(**params).first()
            if user_object:
                return user_object
            return False
        except Exception as e:
            log.error(e, exc_info=True)
            return False

    @staticmethod
    def get_all_users(page=1, size=5):
        """
        Returns all user object from DB.
        """
        try:
            all_data_objects = (
                User.query.filter_by(deleted_at=None)
                .order_by(User.created_at.desc())
                .all()
            )
            json_data = []
            for idx, value in enumerate(all_data_objects):
                json_data.append(all_data_objects[idx].to_response_dict([]))

            return json_data, len(json_data)
        except Exception as e:
            log.error(e, exc_info=True)
            return False
