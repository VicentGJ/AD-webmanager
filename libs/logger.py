import logging
from datetime import datetime
from pythonjsonlogger import jsonlogger


class CustomJsonFormatter(jsonlogger.JsonFormatter):
    def add_fields(self, log_record, record, message_dict):
        super(CustomJsonFormatter, self).add_fields(log_record, record, message_dict)
        if log_record.get('level'):
            log_record['type'] = log_record['level'].upper()
        else:
            log_record['type'] = record.levelname
        if not log_record.get('timestamp'):
            now = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%fZ')
            log_record['date'] = now
        log_record['app'] = record.name


formatter = CustomJsonFormatter('(message)', validate=False)

handler = logging.StreamHandler()
handler.setFormatter(formatter)
logger = logging.getLogger('AD-webmanager')
logger.addHandler(handler)
logger.setLevel(20)
logger.propagate = False


def log_info(message, method, data=None):
    extras = {"method": method} if data is None else {"method": method, "data": data}
    logger.info(message, extra=extras)


def log_debug(message, method, data=None):
    extras = {"method": method} if data is None else {"method": method, "data": data}
    logger.debug(message, extra=extras)


def log_error(message, method, data=None):
    extras = {"method": method} if data is None else {"method": method, "data": data}
    logger.error(message, extra=extras)
