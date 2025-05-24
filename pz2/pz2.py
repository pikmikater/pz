import hashlib
import datetime

class User:
    def __init__(self, login, password):
        self.login = login
        self.pass_hash = hashlib.md5(password.encode()).hexdigest()
        self.active = True
        self.failed_attempts = 0

    def check_pass(self, password):
        return self.pass_hash == hashlib.md5(password.encode()).hexdigest()

class Admin(User):
    def __init__(self, login, password):
        super().__init__(login, password)
        self.access = ["full_control"]

    def give_access(self, access):
        self.access.append(access)

class SimpleUser(User):
    def __init__(self, login, password):
        super().__init__(login, password)
        self.last_visit = None

    def save_login_time(self):
        self.last_visit = datetime.datetime.now()

class Guest(User):
    def __init__(self):
        super().__init__("guest", "")
        self.active = False

class AuthSystem:
    def __init__(self):
        self.users = {}

    def register_user(self, user):
        self.users[user.login] = user

    def sign_in(self, login, password):
        user = self.users.get(login)
        if user and user.check_pass(password) and user.active:
            user.failed_attempts = 0
            self.log_action(f"Вхід: {login} успішно")
            return user
        if user:
            user.failed_attempts += 1
            self.log_action(f"Невдалий вхід: {login}, спроба #{user.failed_attempts}")
        return None

    def log_action(self, message):
        with open("log.txt", "a", encoding="utf-8") as f:
            f.write(f"{datetime.datetime.now()}: {message}\n")

if __name__ == "__main__":
    system = AuthSystem()

    admin = Admin("admin", "4321")
    user = SimpleUser("alice", "qwerty")
    guest = Guest()

    system.register_user(admin)
    system.register_user(user)
    system.register_user(guest)

    print("=== ВХІД У СИСТЕМУ ===")
    login = input("Логін: ")
    password = input("Пароль: ")

    logged_user = system.sign_in(login, password)

    if logged_user:
        print(f"Вхід успішний: {logged_user.login}")
        if type(logged_user) == Admin:
            print(f"Права: {logged_user.access}")
        elif type(logged_user) == SimpleUser:
            logged_user.save_login_time()
            print(f"Останній вхід: {logged_user.last_visit}")
        elif type(logged_user) == Guest:
            print("Обмежений доступ гостя")
    else:
        user = system.users.get(login)
        attempts = user.failed_attempts if user else 0
        print(f"Невірний логін або пароль! Спроба #{attempts}")
        if attempts >= 3:
            print("Забагато невдалих спроб! Акаунт заблоковано!")
