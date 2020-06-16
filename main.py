import os
import importlib
from extras.banners import welcome
from modules.__modules import *

from settings import (
    USABLE_SCRIPTS
)

def log(e):
    with open("error.txt", "a") as file:
        file.write("\n")
        file.write("-" * 60)
        file.write("\n")
        file.write(str(e))
        file.write("\n")
        file.write("-" * 60)


def close():
    print('')
    print('-' * 60)
    print('Closing...')
    print('-' * 60)
    print('')
    exit(0)


def main():
    welcome()

    while True:
        print("\n\n")
        print("-" * 60)

        VALID_OPTIONS = {}

        print("Choose the script you would like to run,")
        for index, script in enumerate(USABLE_SCRIPTS):
            script = script.split(".")[0]
            print("Option {} -> {}".format(index, script))
            VALID_OPTIONS[index] = script
        print("-" * 60)

        while True:
            try:
                script_option = int(input("Choose option: "))
                if script_option in VALID_OPTIONS.keys():
                    script = VALID_OPTIONS[script_option]
                    break
            except KeyboardInterrupt:
                close()
            except Exception as e:
                print("Try again ... ")
            else:
                print("Try again ... ")

        main_func = importlib.import_module("modules." + script)

        try:
            print("\n\n")
            main_func.main()
        except KeyboardInterrupt:
            continue
        except Exception as e:
            print("Exception:", str(e))
            exit(0)


if __name__ == "__main__":
    main()
