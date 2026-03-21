#!/bin/bash 

source ~/./venv/bin/activate

MY_ENV=$(which python3)

echo "[*] Authenticator Portal"
read -p "login or signup [l/s]: " choice

if [ "$choice" == "l" ]; then
  command="login"
  read -p "Email: " email 
  read -sp "Password: " password # -s flag hides the password input

  echo ""

  clear 

  $MY_ENV scan_controller.py $command -u "$email" -p "$password"

elif [ "$choice" == "s" ]; then
  command="register"
  read -p "First Name: " fname
  read -p "Last Name: " lname 
  read -p "Email: " email 
  read -sp "Password: " password # -s flag hides the password input

  echo ""

  clear

  $MY_ENV scan_controller.py $command -f "$fname" -l "$lname" -u "$email" -p "$password"

else
  echo "Invalid option"
  exit 1
fi 

clear
