"""
Contains class and methods for DB interactions for content logging.
"""
import datetime
import json

from Engine import db


class ActionLog(db.Model):
    """
    Class def for content DB.
    """

    __tablename__ = "actions_log"

    id = db.Column(db.Integer, primary_key=True)
    actionable_type = db.Column(db.String)
    action = db.Column(db.String)
    action_id = db.Column(db.Integer)
    meta_data = db.Column(db.String)
    last_updated_at = db.Column(db.DateTime)
    last_edited_by = db.Column(db.String)
    index_save = False

    def __init__(self, data_dict, action, actionable_type, last_edited_by):
        if data_dict is None:
            data_dict = {}
        data_dict["updated_at"] = (
            data_dict.get("updated_at").strftime("%Y-%m-%d %H:%M:%S")
            if data_dict.get("updated_at")
            else datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )
        self.action_id = data_dict.get("id")
        self.action = action
        self.actionable_type = actionable_type
        self.meta_data = json.dumps(data_dict)
        self.last_edited_by = last_edited_by
        super().__init__()

    def create(self):
        """
        Saves the object data to DB and populates ids and dates.
        """
        self.last_updated_at = datetime.datetime.now()
        db.session.add(self)
        # Primary-key attributes are populated immediately within the flush()
        db.session.flush()
        db.session.commit()
