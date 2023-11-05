


from cProfile import label
import sqlite3
import hashlib
from tkinter import *


# Creating the main window screen

window = Tk()

window.title("Password Manager")


#creating the function that requests the user to enter their master password to log into the manager

def loginScreen():
       window.geometry("400x200")
       
       label = Label(window, text="Enter your master password")
       label.config(anchor=CENTER)
       label.pack()
      
 #creating the text box for users to input their password
       txtBox = Entry(window, width=30)
       txtBox.pack()
       txtBox.focus()
       
 #This creates a blank box that will show 'wrong password' if it is entered incorrectly
       label2 = Label(window)
       label2.pack()
       

 #Function that checks the passwork entered by the user and returns if it is correct or not.        
       def CheckPassword():
           password = "testing"
           
           if password == txtBox.get():
               print("correct Password")
           else:
               label2.config(text="wrong Password") 

       button = Button(window, text="confirm", command=CheckPassword)
       button.pack()
       
       

loginScreen()
window.mainloop()
