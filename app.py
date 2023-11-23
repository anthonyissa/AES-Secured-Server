import requests
import bcrypt

def authenticate_user(username):
    with open("bdd.txt", "r", encoding='utf-8') as file:
        for line in file:
            user_info = line.strip().split(',')
            if user_info[0] == username:

                stored_salt = user_info[1]
                stored_encrypt_password = user_info[2]
                return True, stored_salt, stored_encrypt_password
        return False, None, None

def run():
    print("Voulez-vous vous connecter (c) ou vous inscrire (i) ? ")
    reponse = input("Votre réponse : ")
    if reponse == "i" : 
        while True:
            user = input("Votre Id : ")
            login, _, _ = authenticate_user(user)
            if login == True:
                print("Cette username existe déjà !")
            elif login == False:
                break

        password = input("Votre mdp : ").encode('utf-8')
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(password, salt)

        # Envoyer le mot de passe haché
        response = requests.post("http://localhost:8000", data={'login': user, 'hashed_password': hashed_password})

        # Stocker user et salt dans le fichier
        with open("bdd.txt", "a", encoding='utf-8') as file:  # Utilisez "w" si vous souhaitez écraser le fichier
            file.write(user + "," + salt.decode('utf-8') + "," + response.text + "\n")
    elif reponse == "c":
        user = input("Votre Id : ")
        login, stored_salt, stored_encrypt_password = authenticate_user(user)
        if login == False:
            print("Utilisateur inconnu")
            return None
        password = input("Votre mdp : ").encode('utf-8')
        
        hashed_password = bcrypt.hashpw(password, stored_salt.encode('utf-8'))

        # Envoyer le mot de passe haché
        response = requests.post("http://localhost:8000", data={'login': user, 'hashed_password': hashed_password})
        encrypt_res = response.text
        if encrypt_res == stored_encrypt_password:
            print("Bienvenue dans votre compte")
        else:
            print("Mot de passe incorrect")
    else:
        print("Commande non reconnue")
        return None
run()