import json
import hashlib
import os
import tkinter as tk
from tkinter import messagebox, simpledialog, ttk
import pyperclip
from cryptography.fernet import Fernet

class PasswordManagerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("P-MANAGER - Password Manager")
        self.root.geometry("600x500")
        self.root.configure(bg='#2c3e50')
        
        # Initialize encryption
        self.setup_encryption()
        
        # Current logged in user
        self.current_user = None
        
        # Create login screen
        self.create_login_screen()
    
    def setup_encryption(self):
        """Setup encryption key and cipher"""
        key_file = 'encrypt_key.key'
        if os.path.exists(key_file):
            with open(key_file, 'rb') as kf:
                self.key = kf.read()
        else:
            self.key = Fernet.generate_key()
            with open(key_file, 'wb') as kf:
                kf.write(self.key)
        
        self.cipher = Fernet(self.key)
    
    def pwd_hash(self, password):
        """Hash password using SHA-256"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    def encrypt_password(self, password):
        """Encrypt password"""
        return self.cipher.encrypt(password.encode()).decode()
    
    def decrypt_password(self, encrypted_password):
        """Decrypt password"""
        return self.cipher.decrypt(encrypted_password.encode()).decode()
    
    def clear_screen(self):
        """Clear all widgets from screen"""
        for widget in self.root.winfo_children():
            widget.destroy()
    
    def create_login_screen(self):
        """Create the login/register screen"""
        self.clear_screen()
        
        # Title
        title_frame = tk.Frame(self.root, bg='#2c3e50')
        title_frame.pack(pady=30)
        
        tk.Label(title_frame, text="P-MANAGER", font=('Arial', 24, 'bold'), 
                fg='#ecf0f1', bg='#2c3e50').pack()
        tk.Label(title_frame, text="Secure Password Manager", font=('Arial', 12), 
                fg='#bdc3c7', bg='#2c3e50').pack()
        
        # Main frame
        main_frame = tk.Frame(self.root, bg='#34495e', padx=40, pady=30)
        main_frame.pack(pady=20, padx=50, fill='both', expand=True)
        
        # Check if user exists
        if os.path.exists('user_data.json') and os.path.getsize('user_data.json') > 0:
            # Login form
            tk.Label(main_frame, text="LOGIN", font=('Arial', 16, 'bold'), 
                    fg='#ecf0f1', bg='#34495e').pack(pady=(0, 20))
            
            # Username
            tk.Label(main_frame, text="Username:", font=('Arial', 10), 
                    fg='#ecf0f1', bg='#34495e').pack(anchor='w')
            self.username_entry = tk.Entry(main_frame, font=('Arial', 12), width=30)
            self.username_entry.pack(pady=(5, 15), ipady=5)
            
            # Password
            tk.Label(main_frame, text="Password:", font=('Arial', 10), 
                    fg='#ecf0f1', bg='#34495e').pack(anchor='w')
            self.password_entry = tk.Entry(main_frame, show='*', font=('Arial', 12), width=30)
            self.password_entry.pack(pady=(5, 20), ipady=5)
            
            # Login button
            login_btn = tk.Button(main_frame, text="LOGIN", command=self.login,
                                bg='#3498db', fg='white', font=('Arial', 12, 'bold'),
                                width=25, pady=8)
            login_btn.pack(pady=10)
            
        else:
            # Registration form
            tk.Label(main_frame, text="REGISTER", font=('Arial', 16, 'bold'), 
                    fg='#ecf0f1', bg='#34495e').pack(pady=(0, 20))
            
            tk.Label(main_frame, text="Create your admin account:", font=('Arial', 10), 
                    fg='#bdc3c7', bg='#34495e').pack(pady=(0, 15))
            
            # Username
            tk.Label(main_frame, text="Username:", font=('Arial', 10), 
                    fg='#ecf0f1', bg='#34495e').pack(anchor='w')
            self.reg_username_entry = tk.Entry(main_frame, font=('Arial', 12), width=30)
            self.reg_username_entry.pack(pady=(5, 15), ipady=5)
            
            # Password
            tk.Label(main_frame, text="Password:", font=('Arial', 10), 
                    fg='#ecf0f1', bg='#34495e').pack(anchor='w')
            self.reg_password_entry = tk.Entry(main_frame, show='*', font=('Arial', 12), width=30)
            self.reg_password_entry.pack(pady=(5, 20), ipady=5)
            
            # Register button
            register_btn = tk.Button(main_frame, text="REGISTER", command=self.register,
                                   bg='#27ae60', fg='white', font=('Arial', 12, 'bold'),
                                   width=25, pady=8)
            register_btn.pack(pady=10)
    
    def login(self):
        """Handle user login"""
        username = self.username_entry.get().strip()
        password = self.password_entry.get()
        
        if not username or not password:
            messagebox.showerror("Error", "Please fill all fields")
            return
        
        try:
            with open('user_data.json', 'r') as file:
                user_data = json.load(file)
            
            stored_username = user_data.get('username')
            stored_hash = user_data.get('admin_pass')
            entered_hash = self.pwd_hash(password)
            
            if username == stored_username and entered_hash == stored_hash:
                self.current_user = username
                messagebox.showinfo("Success", f"Welcome back, {username}!")
                self.create_main_screen()
            else:
                messagebox.showerror("Error", "Invalid username or password")
        
        except Exception as e:
            messagebox.showerror("Error", f"Login failed: {str(e)}")
    
    def register(self):
        """Handle user registration"""
        username = self.reg_username_entry.get().strip()
        password = self.reg_password_entry.get()
        
        if not username or not password:
            messagebox.showerror("Error", "Please fill all fields")
            return
        
        if len(password) < 6:
            messagebox.showerror("Error", "Password must be at least 6 characters")
            return
        
        try:
            hashed_password = self.pwd_hash(password)
            user_data = {'username': username, 'admin_pass': hashed_password}
            
            with open('user_data.json', 'w') as file:
                json.dump(user_data, file, indent=4)
            
            messagebox.showinfo("Success", "Registration successful!")
            self.create_login_screen()
        
        except Exception as e:
            messagebox.showerror("Error", f"Registration failed: {str(e)}")
    
    def create_main_screen(self):
        """Create the main password manager screen"""
        self.clear_screen()
        
        # Header
        header_frame = tk.Frame(self.root, bg='#2c3e50', pady=10)
        header_frame.pack(fill='x')
        
        tk.Label(header_frame, text=f"Welcome, {self.current_user}!", 
                font=('Arial', 16, 'bold'), fg='#ecf0f1', bg='#2c3e50').pack()
        
        # Logout button
        logout_btn = tk.Button(header_frame, text="Logout", command=self.logout,
                             bg='#e74c3c', fg='white', font=('Arial', 10))
        logout_btn.pack(anchor='ne', padx=20)
        
        # Main content
        content_frame = tk.Frame(self.root, bg='#ecf0f1', padx=20, pady=20)
        content_frame.pack(fill='both', expand=True, padx=20, pady=20)
        
        # Buttons frame
        buttons_frame = tk.Frame(content_frame, bg='#ecf0f1')
        buttons_frame.pack(pady=20)
        
        # Action buttons
        btn_style = {'width': 20, 'pady': 10, 'font': ('Arial', 11, 'bold')}
        
        tk.Button(buttons_frame, text="Add Password", command=self.add_password_dialog,
                 bg='#3498db', fg='white', **btn_style).grid(row=0, column=0, padx=10, pady=5)
        
        tk.Button(buttons_frame, text="Retrieve Password", command=self.retrieve_password_dialog,
                 bg='#2ecc71', fg='white', **btn_style).grid(row=0, column=1, padx=10, pady=5)
        
        tk.Button(buttons_frame, text="View All Websites", command=self.view_websites,
                 bg='#f39c12', fg='white', **btn_style).grid(row=1, column=0, padx=10, pady=5)
        
        tk.Button(buttons_frame, text="Change Password", command=self.change_password_dialog,
                 bg='#9b59b6', fg='white', **btn_style).grid(row=1, column=1, padx=10, pady=5)
        
        tk.Button(buttons_frame, text="Change Admin Info", command=self.change_admin_dialog,
                 bg='#e67e22', fg='white', **btn_style).grid(row=2, column=0, columnspan=2, padx=10, pady=5)
        
        # Websites list
        list_frame = tk.Frame(content_frame, bg='#ecf0f1')
        list_frame.pack(fill='both', expand=True, pady=20)
        
        tk.Label(list_frame, text="Saved Websites:", font=('Arial', 12, 'bold'), 
                bg='#ecf0f1').pack(anchor='w')
        
        # Listbox with scrollbar
        list_container = tk.Frame(list_frame, bg='#ecf0f1')
        list_container.pack(fill='both', expand=True)
        
        scrollbar = ttk.Scrollbar(list_container)
        scrollbar.pack(side='right', fill='y')
        
        self.websites_listbox = tk.Listbox(list_container, yscrollcommand=scrollbar.set,
                                          font=('Arial', 10), height=8)
        self.websites_listbox.pack(side='left', fill='both', expand=True)
        scrollbar.config(command=self.websites_listbox.yview)
        
        # Load websites
        self.refresh_websites_list()
    
    def refresh_websites_list(self):
        """Refresh the websites listbox"""
        self.websites_listbox.delete(0, tk.END)
        
        try:
            if os.path.exists('passwords.json'):
                with open('passwords.json', 'r') as file:
                    passwords = json.load(file)
                
                for entry in passwords:
                    self.websites_listbox.insert(tk.END, entry.get('website', 'Unknown'))
        except:
            pass
    
    def add_password_dialog(self):
        """Dialog to add a new password"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Add Password")
        dialog.geometry("400x200")
        dialog.configure(bg='#34495e')
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Website
        tk.Label(dialog, text="Website/App:", font=('Arial', 10), 
                fg='#ecf0f1', bg='#34495e').pack(pady=10)
        website_entry = tk.Entry(dialog, font=('Arial', 12), width=30)
        website_entry.pack(pady=5)
        
        # Password
        tk.Label(dialog, text="Password:", font=('Arial', 10), 
                fg='#ecf0f1', bg='#34495e').pack(pady=(10, 5))
        password_entry = tk.Entry(dialog, show='*', font=('Arial', 12), width=30)
        password_entry.pack(pady=5)
        
        # Buttons
        btn_frame = tk.Frame(dialog, bg='#34495e')
        btn_frame.pack(pady=20)
        
        def save_password():
            website = website_entry.get().strip()
            password = password_entry.get()
            
            if not website or not password:
                messagebox.showerror("Error", "Please fill all fields")
                return
            
            try:
                # Load existing passwords
                if os.path.exists('passwords.json'):
                    with open('passwords.json', 'r') as file:
                        passwords = json.load(file)
                else:
                    passwords = []
                
                # Add new password
                encrypted_password = self.encrypt_password(password)
                passwords.append({'website': website, 'password': encrypted_password})
                
                # Save
                with open('passwords.json', 'w') as file:
                    json.dump(passwords, file, indent=4)
                
                messagebox.showinfo("Success", "Password added successfully!")
                self.refresh_websites_list()
                dialog.destroy()
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to add password: {str(e)}")
        
        tk.Button(btn_frame, text="Save", command=save_password,
                 bg='#27ae60', fg='white', width=10).pack(side='left', padx=10)
        tk.Button(btn_frame, text="Cancel", command=dialog.destroy,
                 bg='#e74c3c', fg='white', width=10).pack(side='left', padx=10)
    
    def retrieve_password_dialog(self):
        """Dialog to retrieve a password"""
        website = simpledialog.askstring("Retrieve Password", "Enter website/app name:")
        if not website:
            return
        
        try:
            if not os.path.exists('passwords.json'):
                messagebox.showwarning("Warning", "No passwords saved")
                return
            
            with open('passwords.json', 'r') as file:
                passwords = json.load(file)
            
            for entry in passwords:
                if entry.get('website', '').lower() == website.lower():
                    decrypted_password = self.decrypt_password(entry['password'])
                    
                    # Copy to clipboard
                    pyperclip.copy(decrypted_password)
                    
                    # Show password
                    messagebox.showinfo("Password Retrieved", 
                        f"Password for {website}: {decrypted_password}\n\n"
                        "Password copied to clipboard!")
                    return
            
            messagebox.showwarning("Not Found", f"No password found for {website}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to retrieve password: {str(e)}")
    
    def view_websites(self):
        """Show all saved websites"""
        try:
            if not os.path.exists('passwords.json'):
                messagebox.showinfo("Info", "No websites saved")
                return
            
            with open('passwords.json', 'r') as file:
                passwords = json.load(file)
            
            if not passwords:
                messagebox.showinfo("Info", "No websites saved")
                return
            
            websites = [entry.get('website', 'Unknown') for entry in passwords]
            websites_text = "\n".join(f"• {website}" for website in websites)
            
            messagebox.showinfo("Saved Websites", f"Total: {len(websites)} websites\n\n{websites_text}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load websites: {str(e)}")
    
    def change_password_dialog(self):
        """Dialog to change a website password"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Change Password")
        dialog.geometry("400x250")
        dialog.configure(bg='#34495e')
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Website
        tk.Label(dialog, text="Website/App:", font=('Arial', 10), 
                fg='#ecf0f1', bg='#34495e').pack(pady=10)
        website_entry = tk.Entry(dialog, font=('Arial', 12), width=30)
        website_entry.pack(pady=5)
        
        # Old password
        tk.Label(dialog, text="Current Password:", font=('Arial', 10), 
                fg='#ecf0f1', bg='#34495e').pack(pady=(10, 5))
        old_password_entry = tk.Entry(dialog, show='*', font=('Arial', 12), width=30)
        old_password_entry.pack(pady=5)
        
        # New password
        tk.Label(dialog, text="New Password:", font=('Arial', 10), 
                fg='#ecf0f1', bg='#34495e').pack(pady=(10, 5))
        new_password_entry = tk.Entry(dialog, show='*', font=('Arial', 12), width=30)
        new_password_entry.pack(pady=5)
        
        # Buttons
        btn_frame = tk.Frame(dialog, bg='#34495e')
        btn_frame.pack(pady=20)
        
        def update_password():
            website = website_entry.get().strip()
            old_password = old_password_entry.get()
            new_password = new_password_entry.get()
            
            if not website or not old_password or not new_password:
                messagebox.showerror("Error", "Please fill all fields")
                return
            
            try:
                if not os.path.exists('passwords.json'):
                    messagebox.showerror("Error", "No passwords saved")
                    return
                
                with open('passwords.json', 'r') as file:
                    passwords = json.load(file)
                
                for entry in passwords:
                    if entry.get('website', '').lower() == website.lower():
                        current_password = self.decrypt_password(entry['password'])
                        
                        if current_password == old_password:
                            entry['password'] = self.encrypt_password(new_password)
                            
                            with open('passwords.json', 'w') as file:
                                json.dump(passwords, file, indent=4)
                            
                            messagebox.showinfo("Success", "Password updated successfully!")
                            dialog.destroy()
                            return
                        else:
                            messagebox.showerror("Error", "Current password is incorrect")
                            return
                
                messagebox.showerror("Error", f"Website '{website}' not found")
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to update password: {str(e)}")
        
        tk.Button(btn_frame, text="Update", command=update_password,
                 bg='#27ae60', fg='white', width=10).pack(side='left', padx=10)
        tk.Button(btn_frame, text="Cancel", command=dialog.destroy,
                 bg='#e74c3c', fg='white', width=10).pack(side='left', padx=10)
    
    def change_admin_dialog(self):
        """Dialog to change admin credentials"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Change Admin Credentials")
        dialog.geometry("400x300")
        dialog.configure(bg='#34495e')
        dialog.transient(self.root)
        dialog.grab_set()
        
        tk.Label(dialog, text="Change Admin Credentials", font=('Arial', 14, 'bold'), 
                fg='#ecf0f1', bg='#34495e').pack(pady=15)
        
        # Current username
        tk.Label(dialog, text="Current Username:", font=('Arial', 10), 
                fg='#ecf0f1', bg='#34495e').pack(pady=(10, 5))
        current_username_entry = tk.Entry(dialog, font=('Arial', 12), width=30)
        current_username_entry.pack(pady=5)
        current_username_entry.insert(0, self.current_user)
        
        # Current password
        tk.Label(dialog, text="Current Password:", font=('Arial', 10), 
                fg='#ecf0f1', bg='#34495e').pack(pady=(10, 5))
        current_password_entry = tk.Entry(dialog, show='*', font=('Arial', 12), width=30)
        current_password_entry.pack(pady=5)
        
        # New username
        tk.Label(dialog, text="New Username (optional):", font=('Arial', 10), 
                fg='#ecf0f1', bg='#34495e').pack(pady=(10, 5))
        new_username_entry = tk.Entry(dialog, font=('Arial', 12), width=30)
        new_username_entry.pack(pady=5)
        
        # New password
        tk.Label(dialog, text="New Password (optional):", font=('Arial', 10), 
                fg='#ecf0f1', bg='#34495e').pack(pady=(10, 5))
        new_password_entry = tk.Entry(dialog, show='*', font=('Arial', 12), width=30)
        new_password_entry.pack(pady=5)
        
        # Buttons
        btn_frame = tk.Frame(dialog, bg='#34495e')
        btn_frame.pack(pady=20)
        
        def update_admin():
            current_username = current_username_entry.get().strip()
            current_password = current_password_entry.get()
            new_username = new_username_entry.get().strip()
            new_password = new_password_entry.get()
            
            if not current_username or not current_password:
                messagebox.showerror("Error", "Please enter current credentials")
                return
            
            if not new_username and not new_password:
                messagebox.showwarning("Warning", "No changes specified")
                return
            
            try:
                # Verify current credentials
                with open('user_data.json', 'r') as file:
                    user_data = json.load(file)
                
                stored_username = user_data.get('username')
                stored_hash = user_data.get('admin_pass')
                current_hash = self.pwd_hash(current_password)
                
                if current_username != stored_username or current_hash != stored_hash:
                    messagebox.showerror("Error", "Current credentials are incorrect")
                    return
                
                # Update credentials
                if new_username:
                    user_data['username'] = new_username
                    self.current_user = new_username
                
                if new_password:
                    if len(new_password) < 6:
                        messagebox.showerror("Error", "New password must be at least 6 characters")
                        return
                    user_data['admin_pass'] = self.pwd_hash(new_password)
                
                # Save changes
                with open('user_data.json', 'w') as file:
                    json.dump(user_data, file, indent=4)
                
                messagebox.showinfo("Success", "Admin credentials updated successfully!")
                dialog.destroy()
                
                # Refresh main screen to show new username
                self.create_main_screen()
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to update credentials: {str(e)}")
        
        tk.Button(btn_frame, text="Update", command=update_admin,
                 bg='#27ae60', fg='white', width=10).pack(side='left', padx=10)
        tk.Button(btn_frame, text="Cancel", command=dialog.destroy,
                 bg='#e74c3c', fg='white', width=10).pack(side='left', padx=10)
    
    def logout(self):
        """Logout and return to login screen"""
        self.current_user = None
        self.create_login_screen()


def main():
    """Run the GUI application"""
    root = tk.Tk()
    app = PasswordManagerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()