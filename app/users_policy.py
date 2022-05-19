from flask_login import current_user


class UsersPolicy:
    def __init__(self, record=None):
        self.record = record

    def create(self):
        return current_user.is_admin

    def delete(self):
        return current_user.is_admin

    def update(self):
        if self.record is None:
            return False
        else:
            is_editing_user = current_user.id == self.record.id
        return current_user.is_admin or is_editing_user

    def show(self):
        if self.record is None:
            return False
        else:
            is_showing_user = current_user.id == self.record.id
        return current_user.is_admin or is_showing_user

    def assign_role(self):
        return current_user.is_admin
    
    def update_pass(self):
        if self.record is None:
            return False
        else:
            is_editing_user = current_user.id == self.record.id
        return is_editing_user

    def super_user(self):
        return current_user.is_admin