import requests
import subprocess
import re
import logging
from telegram import Update
from telegram.ext import Updater, CommandHandler, MessageHandler, Filters, ConversationHandler, CallbackContext
import paramiko
from dotenv import load_dotenv
import os
from psycopg2 import OperationalError
import psycopg2
from psycopg2 import Error

# Данные для подключения по ssh
SSH_HOST = os.getenv('RM_HOST')
SSH_PORT = os.getenv('RM_PORT')
SSH_USER = os.getenv('RM_USER')
SSH_PASSWORD = os.getenv('RM_PASSWORD')

# Данные для подключения по ssh, чтобы собрать логи (Linux Master)
SSH_HOST_LOG = os.getenv('RM_HOST')
SSH_PORT_LOG = os.getenv('RM_PORT')
SSH_USER_LOG = 'tebelev-danil-nickolaevich'
SSH_PASSWORD_LOG = 'Ulebud10-'

# Данные для подключения к БД
DB_HOST = os.getenv('DB_HOST')
DB_DATABASE = os.getenv('DB_DATABASE')
DB_USER = os.getenv('DB_USER')
DB_PASSWORD = os.getenv('DB_PASSWORD')
DB_PORT = os.getenv('DB_PORT')

# Токен и chat_id
chat_id = '838430676'
token = os.getenv('TOKEN')

# Логирование
LOG_FILE_PATH = "/var/log/postgresql/postgresql.log"
logging.basicConfig(
    filename='logfile.txt', format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO
)
logger = logging.getLogger(__name__)

# Регулярные выражения
EMAIL_REGEX = r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+'
PHONE_REGEX = (r'(8|\+7)\d{10}|(8|\+7)\(\d{3}\)\d{7}|(8|\+7) \d{3} \d{3} \d{2} \d{2}|(8|\+7) \(\d{3}\) \d{3} \d{2} \d{2}|(8|\+7)-\d{3}-\d{3}-\d{2}-\d{2}|8 \(\d{3}\) \d{3}-\d{2}-\d{2}')
PASSWORD_REGEX = r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[!@#$%^&*()])[A-Za-z\d!@#$%^&*()]{8,}$'


def get_db_data(update: Update, context: CallbackContext, query):
    try:
        conn = psycopg2.connect(dbname=DB_DATABASE, user=DB_USER, password=DB_PASSWORD, host=DB_HOST, port=DB_PORT)
        cur = conn.cursor()
        cur.execute(query)
        rows = cur.fetchall()
        if rows:
            message_text = "\n".join(f"{row[0]}: {row[1]}" for row in rows)
        else:
            message_text = "Данные не найдены."
        update.message.reply_text(message_text)
        cur.close()
        conn.close()
    except (Exception, psycopg2.DatabaseError) as error:
        logger.error(f"Database error: {error}")
        update.message.reply_text('Ошибка базы данных.')

def get_emails(update, context: CallbackContext):
    update.message.reply_text('flag_3')
    get_db_data(update, context, "SELECT id, email FROM emails")


def get_phone_numbers(update, context: CallbackContext):
    get_db_data(update, context, "SELECT id, phone_number FROM phone_numbers")

def get_logs_via_ssh():
    try:
        # Создаем SSH-клиент
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(SSH_HOST_LOG, port=SSH_PORT_LOG, username=SSH_USER_LOG, password=SSH_PASSWORD_LOG)

        # Команда для чтения последних 10 строк логов
        command = f"cat {LOG_FILE_PATH} | grep repl | tail -n 15"
        stdin, stdout, stderr = ssh.exec_command(command)

        # Получаем вывод команды
        logs = stdout.read().decode('utf-8')
        ssh.close()

        if logs:
            return logs
        else:
            return "Логи не найдены или файл логов пуст."
    except paramiko.SSHException as e:
        return f"Ошибка SSH подключения: {str(e)}"
def get_repl_logs(update, context):
    logs = get_logs_via_ssh()
    update.message.reply_text(f'Логи репликации:\n{logs}')


#---------------------------------------------------------------------------------------------#

# Поиск email
def findEmailsCommand(update: Update, context):
    update.message.reply_text('Введите текст для поиска email:')
    return 'findEmail'

# Поиск email
def findEmail(update: Update, context):
    user_input = update.message.text
    emailRegxList = re.findall(EMAIL_REGEX, user_input)

    if not emailRegxList:
        update.message.reply_text('Email-адреса не найдены.')
        return ConversationHandler.END

    email = '\n'.join(f'{i + 1}. {email}' for i, email in enumerate(emailRegxList))
    update.message.reply_text(f'Найдены следующие email:\n{email}')

    update.message.reply_text('Хотите сохранить найденные email адреса в базе данных? Отправьте "Да" или "Нет".')
    print(emailRegxList)
    context.user_data['emails'] = emailRegxList
    return 'handle_save_emails'

def handle_save_emails(update: Update, context):
    response = update.message.text.lower()
    if response == 'да':
        emails = context.user_data['emails']
        save_email_to_db(emails)
        update.message.reply_text('Email адреса успешно сохранены в базе данных.')
    elif response == 'нет':
        update.message.reply_text('Email адреса не сохранены.')
    else:
        update.message.reply_text('Пожалуйста, отправьте "Да" или "Нет".')
    return ConversationHandler.END


def save_email_to_db(emails):
    conn = psycopg2.connect(dbname=DB_DATABASE, user=DB_USER, password=DB_PASSWORD, host=DB_HOST, port=DB_PORT)
    cur = conn.cursor()
    for email in emails:
        cur.execute("INSERT INTO emails (email) VALUES (%s) ON CONFLICT DO NOTHING", (email,))
    print(3)
    conn.commit()
    cur.close()
    conn.close()
    return ConversationHandler.END


def confirm_email_saving(update, context):
    email = context.user_data.get('email_to_save')
    if save_email_to_db(email):
        update.message.reply_text(f'Email {email} успешно сохранен в базе данных.')
    else:
        update.message.reply_text(f'Ошибка при сохранении email {email}.')
    return ConversationHandler.END


#---------------------------------------------------------------------------------------------#
# Поиск номеров телефонов
def findPhoneNumbersCommand(update: Update, context):
    update.message.reply_text('Введите текст для поиска телефонных номеров:')
    return 'findPhoneNumbers'

# Поиск номеров телефонов
def findPhoneNumbers(update: Update, context):
    user_input = update.message.text
    PHONE_REGEX = r'(\+7|8)[-\s]?\(?(\d{3})\)?[-\s]?(\d{3})[-\s]?(\d{2})[-\s]?(\d{2})'
    phoneNumberList = re.findall(PHONE_REGEX, user_input)
    if not phoneNumberList:
        update.message.reply_text('Телефонные номера не найдены.')
        return ConversationHandler.END
    formatted_phone_numbers = []
    for phone in phoneNumberList:
        formatted_phone = f'{phone[0]} ({phone[1]}) {phone[2]}-{phone[3]}-{phone[4]}'
        formatted_phone_numbers.append(formatted_phone)
    phoneNumbers = ''  # Создаем строку, в которую будем записывать номера телефонов
    for i in range(len(phoneNumberList)):
        phoneNumbers += f'{i + 1}. {phoneNumberList[i]}\n'  # Записываем очередной номер

    result = '\n'.join(f'{i + 1}. {phone}' for i, phone in enumerate(formatted_phone_numbers))
    update.message.reply_text(f'Найдены следующие номера телефонов:\n{result}\n')
    update.message.reply_text('Хотите ли вы сохранить данные в бд?')
    context.user_data['phones'] = formatted_phone_numbers
    return 'handle_save_phones'

def handle_save_phones(update: Update, context):
    response = update.message.text.lower()
    phones = context.user_data.get('phones')

    print("Response:", response)
    print("Phones:", phones)

    if response == 'да':
        save_phone_number_to_db(phones)
        update.message.reply_text('Номера успешно сохранены!')
    elif response == 'нет':
        update.message.reply_text('Номера не сохранены.')
    else:
        update.message.reply_text('Пожалуйста, отправьте "Да" или "Нет".')
    return ConversationHandler.END

def save_phone_number_to_db(phones):
    conn = psycopg2.connect(dbname=DB_DATABASE, user=DB_USER, password=DB_PASSWORD, host=DB_HOST, port=DB_PORT)
    cur = conn.cursor()
    for number in phones:
        cur.execute("INSERT INTO phone_numbers (phone_number) VALUES (%s) ON CONFLICT DO NOTHING", (number,))
    conn.commit()
    cur.close()
    conn.close()

def confirm_phone_number_saving(update, context):
    phone_number = context.user_data.get('phone_number_to_save')
    if save_phone_number_to_db(phone_number):
        update.message.reply_text(f'Номер телефона {phone_number} успешно сохранен в базе данных.')
    else:
        update.message.reply_text(f'Ошибка при сохранении номера телефона {phone_number}.')
    return ConversationHandler.END


#---------------------------------------------------------------------------------------------#
# Подключение к серверу по ssh
def ssh_command(command):
    try:
        # Устанавливаем SSH-соединение
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(SSH_HOST, port=SSH_PORT, username=SSH_USER, password=SSH_PASSWORD)

        # Выполняем команду на сервере
        stdin, stdout, stderr = ssh.exec_command(command)
        output = stdout.read().decode('utf-8')
        ssh.close()
        return output.strip()  # Возвращаем результат выполнения команды
    except Exception as e:
        return f"Ошибка подключения: {str(e)}"

# Получение релизной информации
def get_release(update, context):
    command = 'cat /etc/os-release'
    output = ssh_command(command)
    update.message.reply_text(f'Информация о релизе:\n{output}')

# Информация об архитектуре, имени хоста и версии ядра
def get_uname(update, context):
    command = 'uname -a'
    output = ssh_command(command)
    update.message.reply_text(f'Информация о системе:\n{output}')

# Время работы системы
def get_uptime(update, context):
    command = 'uptime'
    output = ssh_command(command)
    update.message.reply_text(f'Время работы системы:\n{output}')

# Состояние файловой системы
def get_df(update, context):
    command = 'df -h'
    output = ssh_command(command)
    update.message.reply_text(f'Состояние файловой системы:\n{output}')

# Состояние оперативной памяти
def get_free(update, context):
    command = 'free -h'
    output = ssh_command(command)
    update.message.reply_text(f'Состояние оперативной памяти:\n{output}')

# Производительность системы
def get_mpstat(update, context):
    command = 'mpstat'
    output = ssh_command(command)
    update.message.reply_text(f'Производительность системы:\n{output}')

# Информация о пользователях
def get_w(update, context):
    command = 'w'
    output = ssh_command(command)
    update.message.reply_text(f'Информация о пользователях:\n{output}')

# Логи - последние 10 входов
def get_auths(update, context):
    command = 'last -n 10'
    output = ssh_command(command)
    update.message.reply_text(f'Последние 10 входов:\n{output}')

# Последние 5 критических событий
def get_critical(update, context):
    command = 'journalctl -p crit -n 5'
    output = ssh_command(command)
    update.message.reply_text(f'Последние 5 критических событий:\n{output}')

# Список процессов
def get_ps(update, context):
    command = 'ps aux'
    output = ssh_command(command)
    update.message.reply_text(f'Список процессов:\n{output}')

# Состояние портов
def get_ss(update, context):
    command = 'ss -tuln'
    output = ssh_command(command)
    update.message.reply_text(f'Состояние портов:\n{output}')

# Установленные пакеты
def get_apt_list(update, context):
    command = 'apt list --installed'
    output = ssh_command(command)
    update.message.reply_text(f'Список установленных пакетов:\n{output}')

# Поиск информации о конкретном пакете
def get_apt_package(update, context):
    package_name = context.args[0]  # Получаем имя пакета от пользователя
    command = f'apt show {package_name}'
    output = ssh_command(command)
    update.message.reply_text(f'Информация о пакете {package_name}:\n{output}')

# Список запущенных сервисов
def get_services(update, context):
    command = 'systemctl list-units --type=service --state=running'
    output = ssh_command(command)
    update.message.reply_text(f'Список запущенных сервисов:\n{output}')

# Отправка сообщения через API Telegram
def send_message(token, chat_id, text):
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": text
    }
    response = requests.post(url, json=payload)
    if response.status_code == 200:
        logger.info("Сообщение успешно отправлено!")
    else:
        logger.error(f"Ошибка при отправке сообщения: {response.text}")

# Проверка сложности пароля
def verifyPasswordCommand(update: Update, context):
    update.message.reply_text('Введите пароль для проверки его сложности:')
    return 'verifyPassword'

# Проверка пароля
def verifyPassword(update: Update, context):
    user_input = update.message.text

    if re.match(PASSWORD_REGEX, user_input):
        update.message.reply_text('Пароль сложный')
    else:
        update.message.reply_text('Пароль простой')

    return ConversationHandler.END

def get_repl_logs(update: Update, context: CallbackContext) -> None:
    try:
        result = subprocess.run(
            ["bash", "-c", f"cat {LOG_FILE_PATH} | grep repl | tail -n 15"],
            capture_output=True,
            text=True
        )
        logs = result.stdout
        if logs:
            update.message.reply_text(f"Последние репликационные логи:\n{logs}")
        else:
            update.message.reply_text("Репликационные логи не найдены.")
    except Exception as e:
        update.message.reply_text(f"Ошибка при получении логов: {str(e)}")


def start(update: Update, context):
    user = update.effective_user
    update.message.reply_text(f'Привет, {user.full_name}! Чем могу помочь?')

def echo(update: Update, context):
    update.message.reply_text(update.message.text)

def main():
    updater = Updater(token, use_context=True)
    dp = updater.dispatcher

    # Для поиска email
    convHandlerFindEmail = ConversationHandler(
        entry_points=[CommandHandler('find_email', findEmailsCommand)],
        states={
            'findEmail': [MessageHandler(Filters.text & ~Filters.command, findEmail)],
            'handle_save_emails': [MessageHandler(Filters.text, handle_save_emails)]
        },
        fallbacks=[]
    )

    # Для поиска номеров телефонов
    convHandlerFindPhoneNumbers = ConversationHandler(
        entry_points=[CommandHandler('find_phone_numbers', findPhoneNumbersCommand)],
        states={
            'findPhoneNumbers': [MessageHandler(Filters.text & ~Filters.command, findPhoneNumbers)],
            'handle_save_phones': [MessageHandler(Filters.text, handle_save_phones)]
        },
        fallbacks=[]
    )

    # Проверка пароля
    convHandlerVerifyPassword = ConversationHandler(
        entry_points=[CommandHandler('verify_password', verifyPasswordCommand)],
        states={
            'verifyPassword': [MessageHandler(Filters.text & ~Filters.command, verifyPassword)],
        },
        fallbacks=[]
    )
    repl_logs_handler = CommandHandler('get_repl_logs', get_repl_logs)

    # Обработчики команд по ssh
    dp.add_handler(CommandHandler("get_release", get_release))
    dp.add_handler(CommandHandler("get_uname", get_uname))
    dp.add_handler(CommandHandler("get_uptime", get_uptime))
    dp.add_handler(CommandHandler("get_df", get_df))
    dp.add_handler(CommandHandler("get_free", get_free))
    dp.add_handler(CommandHandler("get_mpstat", get_mpstat))
    dp.add_handler(CommandHandler("get_w", get_w))
    dp.add_handler(CommandHandler("get_auths", get_auths))
    dp.add_handler(CommandHandler("get_critical", get_critical))
    dp.add_handler(CommandHandler("get_ps", get_ps))
    dp.add_handler(CommandHandler("get_ss", get_ss))
    dp.add_handler(CommandHandler("get_apt_list", get_apt_list))
    dp.add_handler(CommandHandler("get_apt_package", get_apt_package, pass_args=True))
    dp.add_handler(CommandHandler("get_services", get_services))

    # Добавляем обработчики команд
    dp.add_handler(convHandlerFindEmail)
    dp.add_handler(convHandlerFindPhoneNumbers)
    dp.add_handler(convHandlerVerifyPassword)
    dp.add_handler(CommandHandler("start", start))
    dp.add_handler(MessageHandler(Filters.text & ~Filters.command, echo))


    # Обработчики команд с бд

    dp.add_handler(CommandHandler("get_emails", get_emails))
    dp.add_handler(CommandHandler("get_phone_numbers", get_phone_numbers))
    dp.add_handler(repl_logs_handler)

    # Запуск бота
    updater.start_polling()
    updater.idle()

if __name__ == '__main__':
    main()
