"""
Contains base model for all models to inherit data and methods from.
"""
import datetime
import logging as log
import threading

from flask import g
from sqlalchemy import text, asc, desc

from Engine import db
from Engine.models.generic import action_logging


class Base(db.Model):
    """
    Base class def for other children classes.
    """

    __abstract__ = True

    created_at = db.Column(db.DateTime)
    updated_at = db.Column(db.DateTime)
    group_id = db.Column(db.Integer)
    deleted_at = db.Column(db.DateTime)

    def __init__(self, created_at, updated_at, group_id, deleted_at):
        self.created_at = created_at  # db.Column(db.DateTime, default=db.func.now())
        self.updated_at = updated_at  # db.Column(db.DateTime, default=db.func.now(), onupdate=db.func.now())
        self.deleted_at = None

    def to_response_dict(self, skip_list=[]):
        """
        Creates a dict for sending a response to user.
        """
        return None

    def to_db_storable_dict(self, skip_list):
        """
        Creates a dict for saving object to DB.
        """
        return None

    def create(self, caller="content"):
        """
        Saves the object data to DB and populates ids and dates.
        """
        self.created_at = datetime.datetime.now()
        self.updated_at = datetime.datetime.now()
        db.session.add(self)
        # Primary-key attributes are populated immediately within the flush()
        db.session.flush()
        db.session.commit()
        if self.index_save:
            # External hooks
            pass

    def update(self, filter_param, update_params):
        """
        Updates the object data to DB.
        """
        self.updated_at = datetime.datetime.now()
        update_params["updated_at"] = self.updated_at
        db.session.query(self.__class__).filter_by(**filter_param).update(update_params)
        db.session.commit()
        if self.index_save:
            # External hooks
            pass
        thread = threading.Thread(
            target=action_logging.ActionLog(
                data_dict=update_params,
                action="update",
                actionable_type=self.get_class_name(),
                last_edited_by=g.user_id,
            ).create(),
            daemon=True,
            args=(),
        )
        thread.start()

    def update_v2(self, *filter_param, update_params):
        """
        Updates the object data to DB.
        """
        self.updated_at = datetime.datetime.now()
        log.info(f"update params: {update_params}")
        update_params["updated_at"] = self.updated_at
        db.session.query(self.__class__).filter(*filter_param).update(
            update_params, synchronize_session="fetch"
        )
        db.session.commit()
        if self.index_save:
            # External hooks
            pass
        thread = threading.Thread(
            target=action_logging.ActionLog(
                data_dict=update_params,
                action="update",
                actionable_type=self.get_class_name(),
                last_edited_by=g.user_id,
            ).create(),
            daemon=True,
            args=(),
        )
        thread.start()

    def delete(self, filter_param):
        """
        Sets status of object as False in DB
        """
        self.deleted_at = datetime.datetime.now()
        db.session.query(self.__class__).filter_by(**filter_param).update(
            {"deleted_at": self.deleted_at}
        )

        db.session.commit()
        if self.index_save:
            # External hooks
            pass
        thread = threading.Thread(
            target=action_logging.ActionLog(
                data_dict=None,
                action="delete",
                actionable_type=self.get_class_name(),
                last_edited_by=g.user_id,
            ).create(),
            daemon=True,
            args=(),
        )
        thread.start()

    def fetch_by_id(self, params):
        """
        Fetches data from DB by id or all data.
        """
        params["deleted_at"] = None
        data_object = db.session.query(self.__class__).filter_by(**params).first()
        if data_object:
            returnable_json_data = data_object.to_response_dict()
            return returnable_json_data
        return False

    def fetch_by_col(self, params, sort_by, order="asc"):
        """
        Fetches data from DB where they match the query by column.
        """
        if order == "asc":
            all_data_objects = (
                db.session.query(self.__class__)
                .filter_by(**params)
                .order_by(asc(sort_by))
                .all()
            )
        else:
            all_data_objects = (
                db.session.query(self.__class__)
                .filter_by(**params)
                .order_by(desc(sort_by))
                .all()
            )
        all_returnable_json_data = [
            json_data.to_response_dict()
            for json_data in all_data_objects
            if json_data.deleted_at is None
        ]
        return all_returnable_json_data

    def get_class_name(self):
        return self.__class__.__name__

    def fetch_by_provided_data(self, params, sort_by, order):
        if order == "asc":
            multiple_objects = (
                db.session.query(self.__class__)
                .filter_by(**params)
                .order_by(asc(sort_by))
                .all()
            )
        else:
            multiple_objects = (
                db.session.query(self.__class__)
                .filter_by(**params)
                .order_by(desc(sort_by))
                .all()
            )
        all_returnable_json_data = [
            json_data.to_response_dict()
            for json_data in multiple_objects
            if json_data.deleted_at is None
        ]
        if all_returnable_json_data:
            return all_returnable_json_data
        return False

    def search_by_char(self, key, col_name: list):
        """
        Fetch by char in db
        """
        try:
            json_data = []
            for col in col_name:
                all_data_objects = (
                    db.session.query(self.__class__)
                    .filter(getattr(self.__class__, col).ilike(f"%{key.lower()}%"))
                    .all()
                )
                for idx, value in enumerate(all_data_objects):
                    if all_data_objects[idx].deleted_at is None:
                        json_data.append(all_data_objects[idx].to_response_dict([]))
            result = list({v["id"]: v for v in json_data}.values())
            return result
        except Exception as e:
            log.error(e, exc_info=True)
            return False

    def filter_query(
        model_class, query, filter_condition, order, sort_by, raw_query=""
    ):
        """
        Return filtered queryset based on condition
        :param model_class: class object
        :param order: order
        :param sort_by: sort by field
        :param query: takes query
        :param raw_query: raw sql query very rare case
        :param filter_condition: Its a list, ie: [(key,operator,value)]
        operator list:
            eq for ==
            lt for <
            ge for >=
            in for in_
            like for like
            value could be list or a Str
        :return: queryset
        """
        if query is None:
            query = db.session.query(model_class)
            if raw_query:
                query = query.filter(text(raw_query))

        for raw in filter_condition:
            try:
                key, op, value = raw
            except ValueError:
                raise Exception("Invalid filter: %s" % raw)
            column = getattr(model_class, key, None)
            if not column:
                raise Exception("Invalid filter column: %s" % key)
            if op == "in":
                if isinstance(value, list):
                    filt = column.in_(value)
                else:
                    filt = column.in_(value.split(","))
            elif op == "between":
                if isinstance(value, list):
                    filt = column.between(value[0], value[1])
            else:
                try:
                    attr = (
                        list(
                            filter(
                                lambda e: hasattr(column, e % op),
                                ["%s", "%s_", "__%s__"],
                            )
                        )[0]
                        % op
                    )
                except IndexError:
                    raise Exception("Invalid filter operator: %s" % op)
                if value == "null":
                    value = None

                filt = getattr(column, attr)(value)
            query = query.filter(filt)
        if order and sort_by:
            if order == "asc":
                query = query.order_by(asc(sort_by))
            else:
                query = query.order_by(desc(sort_by))
            return query
        return query
