import bcrypt
import os
from pwinput import pwinput  # type: ignore
from cryptography.fernet import Fernet


def pwd_manager(fernet: Fernet) -> None:
    """
    Manages user passwords and entries based on user input. 
    Takes in a Fernet object for encryption and decryption. 
    Does not return any value.
    """

    user_action = input(
        "\nChoose action (enter number):\n 1. view all entries\n 2. view password\n 3. add entry\n 4. quit\n\n")
    print("")

    match user_action.lower():
        case "4":
            quit()
        case"1":
            if not os.path.exists("./entries.txt"):
                print("The list is empty.")
                pwd_manager(fernet)
            with open("./entries.txt", "r") as f:
                entries = f.readlines()
                for i in range(len(entries)):
                    entry_name = entries[i].split(":")[0]
                    print(f"{i + 1}) {entry_name}")
        case "2":
            if not os.path.exists("./entries.txt"):
                print("The list is empty.")
                pwd_manager(fernet)
            entry_name = input("Enter the name of the entry: ")
            with open("./entries.txt", "r") as f:
                entries = f.readlines()
                entries_labels = [entry.split(":")[0] for entry in entries]
                if entry_name in entries_labels:
                    target_entry = entries[entries_labels.index(
                        entry_name)].split(":")
                    decrypted_pwd = fernet.decrypt(target_entry[1].encode())
                    print(
                        f"\nentry name: {target_entry[0]}\npassword: {decrypted_pwd.decode()}")
                else:
                    print("The entry is not found. Please try again.")
        case "3":
            entry_name = input("Enter the entry name: ")
            entry_pwd = pwinput("Enter the password: ").encode()
            print("")
            with open("./entries.txt", "a") as f:
                encrypted_pwd = fernet.encrypt(entry_pwd)
                f.write(f"{entry_name}:{encrypted_pwd.decode()}\n")
        case _:
            print("Incorrect input, please try again.")

    pwd_manager(fernet)


def greeting() -> None:
    """
    This function greets the user and prompts for a master password. If the .key.key file
    exists, it reads the keys and attempts to validate the master password. If the file 
    does not exist, it prompts the user to create a master password and generates the 
    required keys. 
    """
    print("\n***************")
    print("Welcome to PWD")
    print("***************\n")

    if os.path.exists("./.key.key"):
        attempts = 3
        f_key: bytes
        fernet: Fernet
        with open("./.key.key", "r") as f:
            keys = f.readlines()
            hashed_master_pwd = keys[0].strip().encode()
            while attempts:
                master_pwd = pwinput(
                    f"Enter the master password ({attempts} attempts): ").encode()
                if bcrypt.checkpw(master_pwd, hashed_master_pwd):
                    f_key = keys[1].encode()
                    fernet = Fernet(f_key)
                    pwd_manager(fernet)
                    break
                else:
                    print("Incorrect password\n")
                    attempts -= 1
    else:
        master_pwd = pwinput(
            "Create the master password (min length 7 characters): ").encode()
        hashed_master_pwd = bcrypt.hashpw(master_pwd, bcrypt.gensalt())
        f_key = Fernet.generate_key()
        fernet = Fernet(f_key)
        with open("./.key.key", mode="a") as f:
            f.write(f"{hashed_master_pwd.decode()}\n{f_key.decode()}")
        pwd_manager(fernet)


greeting()
