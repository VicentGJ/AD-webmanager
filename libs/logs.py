import sys
from datetime import datetime

from libs.logger import log_info, log_error
from utils import constants

def logs(logs_params):
    def decorator(function):
        def wrapper(*args, **kwargs):

            print_logs = {param: kwargs[param] for param in logs_params if param in kwargs}
            try:

                log_info(constants.LOG_INIT, function.__name__, print_logs)
                init = datetime.now()
                result = function(*args, **kwargs)
                end = datetime.now()
                log_info(constants.LOG_OK, function.__name__, {'execute time': end - init, **print_logs})
                return result
            except Exception as e:
                log_error(constants.LOG_EX, function.__name__, {"error": sys.exc_info(), **print_logs})
                return {"error": "error ocurred"}, 500
        wrapper.__name__ = function.__name__
        return wrapper
    return decorator
