import secrets
import os
from reNgine.utils.logger import default_logger as logger



'''
Based on
https://github.com/MobSF/Mobile-Security-Framework-MobSF/blob/master/MobSF/init.py
'''


def first_run(secret_file, base_dir):
    if 'RENGINE_SECRET_KEY' in os.environ:
        secret_key = os.environ['RENGINE_SECRET_KEY']
    elif os.path.isfile(secret_file):
        secret_key = open(secret_file).read().strip()
    else:
        try:
            secret_key = get_random()
            with open(secret_file, 'w') as secret:
                secret.write(secret_key)
        except OSError as e:
            logger.exception(f'Secret file generation failed. Path: {secret_file}')
            raise Exception(f'Secret file generation failed. Path: {secret_file}') from e
    return secret_key


def get_random():
    charlist = 'abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*(-_=+)'
    return ''.join(secrets.choice(charlist) for _ in range(64))
