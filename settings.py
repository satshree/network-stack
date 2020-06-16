""" SETTINGS FOR 'main.py' """
__author__ = "Satshree Shrestha"


import os


# ROOT DIRECTORY
ROOT_PATH = os.path.dirname(os.path.abspath(__file__))


# PATH WHERE ALL THE SCRIPTS ARE KEPT
MODULES_PATH = "./modules"


# IGNORE THESE FILES WHILE LOOKING FOR SCRIPTS INSIDE './modules'
IGNORE_FILES = (
    '__common.py',
    '__modules.py',
    'database.txt'
)


# GENERATE LIST OF USABLE SCRIPTS AUTOMATICALLY SO NO NEW SCRIPTS HAVE TO BE REGISTERED SOMEWHERE HERE IN SETTINGS
def get_script_list():
    """ GET LIST OF USABLE SCRIPTS. """

    for path, folder, files in os.walk(MODULES_PATH):
        if path == MODULES_PATH:
            for file in IGNORE_FILES:
                del files[files.index(file)]

            return files


# USE THIS LIST INSTEAD OF CALLING THE FUNCTION 'get_script_list'
USABLE_SCRIPTS = get_script_list()
