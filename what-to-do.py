from tkinter import *
import customtkinter as ctk
from PIL import Image
import os
from CTkMessagebox import CTkMessagebox
from backend.exceptions import *
from backend.app_backend import register_account, get_name, signin_account, change_password, add_new_task, get_all_task,delete_task, update_status, update_count
from middleware.account import AccountRegistration, AccountSignIn, ChangePassword, TaskCreation




#Application Width and Height
appWidth, appHeight = 900, 600

# Assets Path
asset_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'Assets')

#Colors
text_primary = '#1E1E1E'
text_secondary = '#F5F5F5'
text_tertiary = '#9DB2BF'
text_error = '#F84B4B'
button_default = '#b553a0'
button_secondary = '#E8E8E8'
button_hover = '#b553a0'
button_secondary_hover = '#b553a0'
widget_color = '#d7b5d4'
todo_banner_color = '#ad5ea5'
done_banner_color = '#f08dec'

#Font Styles
font_heading = ('Times New Roman', 26, 'bold')
font_subheading = ('Times New Roman', 24, 'bold')
font_body_18 = ('Times New Roman', 18)
font_body_18_overstrike = ('Times New Roman', 18, 'overstrike')
font_body_16 = ('Times New Roman', 16)
font_error = ('Times New Roman', 16)

# Load Image Icons
show_icon = ctk.CTkImage(Image.open(os.path.join(asset_path, 'show-outline.png')),
                         size=(20, 20))
hide_icon = ctk.CTkImage(Image.open(os.path.join(asset_path, 'hide-outline.png')),
                         size=(20, 20))

error_icon = ctk.CTkImage(Image.open(os.path.join(asset_path, 'error.png')),
                          size=(20, 20))
check_icon = ctk.CTkImage(Image.open(os.path.join(asset_path, 'check.png')),
                          size=(20, 20))

profile_icon = ctk.CTkImage(Image.open(os.path.join(asset_path, 'profile.png')),
                            size=(20, 20))
email_icon = ctk.CTkImage(Image.open(os.path.join(asset_path, 'email.png')),
                          size=(20, 20))
password_icon = ctk.CTkImage(Image.open(os.path.join(asset_path, 'key.png')),
                             size=(20, 20))

delete_icon = ctk.CTkImage(Image.open(os.path.join(asset_path, 'delete.png')),
                           size=(20, 20))


def create_button(master, text, command, width=140):
    button = ctk.CTkButton(master, text=text, text_color=text_secondary, height=35, width=width, cursor='hand2',
                           font=font_body_16, corner_radius=18, fg_color=button_default,
                           hover_color=button_hover, command=command)

    return button


def create_secondary_button(master, text, command, width=140):
    button = ctk.CTkButton(master, text=text, text_color=text_primary, height=35, width=width,
                           font=font_body_16, corner_radius=18, fg_color=button_secondary,
                           hover_color=button_secondary_hover, command=command)

    return button


def create_entry_widget(master, text, icon=None, valid_icon=None, show='', validate_command=None):
    frame = ctk.CTkFrame(master, fg_color=widget_color, corner_radius=18)
    frame.columnconfigure(0, weight=1)

    entry = ctk.CTkEntry(frame, placeholder_text=text,
                         fg_color='transparent',
                         text_color=text_primary, font=font_body_16,
                         justify='center', border_width=0, corner_radius=0,
                         show=show, validatecommand=validate_command, validate='focusout')
    entry.grid(row=0, column=0, columnspan=2, padx=10, pady=3, sticky='nsew')

    valid_icon_label = ctk.CTkLabel(frame, text='', image=valid_icon)
    valid_icon_label.grid(row=0, column=0, padx=15, sticky='w')

    icon_label = ctk.CTkLabel(frame, text='', image=icon, cursor='hand2')
    icon_label.grid(row=0, column=1, padx=15, sticky='e')

    return frame


def create_error_label(master):
    error_label = ctk.CTkLabel(master, text='', text_color=text_error, font=font_error)

    return error_label


def password_toggle(widget, state):
    if not state:
        widget.winfo_children()[0].configure(show='')
        widget.winfo_children()[2].configure(image=hide_icon)
        return True
    else:
        widget.winfo_children()[0].configure(show='•')
        widget.winfo_children()[2].configure(image=show_icon)
        return False


def have_account(master, label, text):
    frame = ctk.CTkFrame(master, fg_color='transparent', corner_radius=0)

    have_account_label = ctk.CTkLabel(frame, text=label, text_color=text_primary,
                                      font=font_body_16)
    have_account_label.grid(row=0, column=0, padx=(45, 5))

    text_label = ctk.CTkLabel(frame, text=text, text_color=button_hover,
                              font=font_subheading, cursor='hand2')
    text_label.grid(row=0, column=1, padx=(5, 20))

    return frame


def create_banner(master, banner_label, color):
    frame = ctk.CTkFrame(master, fg_color=color, corner_radius=0,)

    label = ctk.CTkLabel(frame, text=banner_label, text_color=text_secondary, font=font_body_16, width=30)
    label.grid(row=0, column=0, padx=20, pady=5, sticky='nsew')

    count = ctk.CTkLabel(frame, text='0', text_color=text_secondary, font=font_subheading, width=30)
    count.grid(row=0, column=1, padx=10, pady=5, sticky='nsew')

    return frame


class App(ctk.CTk):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Create window
        x = (self.winfo_screenwidth() // 2) - (appWidth // 2)
        y = (self.winfo_screenheight() // 2) - (appHeight // 2)
        self.geometry(f'{appWidth}x{appHeight}+{x}+{y}')
        self.resizable(False, False)
        self.title('Notes App')
        self.iconbitmap('Assets/task.ico')
        self.bg_image = ctk.CTkImage(Image.open(os.path.join(asset_path, 'office-desk.png')), size=(400, 450))
        self.frame = ctk.CTkFrame(self, fg_color='#f7edf7', corner_radius=20)
        self.frame.pack(fill='both', expand=True)
        # Configure frame grid layout
        self.frame.columnconfigure(0, weight=1, uniform='a')
        self.frame.columnconfigure(1, weight=1, uniform='a')

        self.frame.rowconfigure(0, weight=1)

        self.bg_image_label = ctk.CTkLabel(self.frame, text='', image=self.bg_image)
        self.bg_image_label.grid(row=0, column=0, columnspan=2, sticky='sew')

        self.title_label = ctk.CTkLabel(self.frame, text='What plans do you have for today?', text_color=text_primary,
                                        font=font_heading)
        self.title_label.grid(row=0, column=0, padx=20, pady=20, sticky='nw')

        self.get_started_frame = GetStartedFrame(self.frame, fg_color='transparent', corner_radius=0,
                                                 command=self.get_started_button_event)
        self.get_started_frame.grid(row=0, column=1, sticky='nsew')

        self.signin_frame = SignInFrame(self.frame, fg_color='transparent', corner_radius=0,
                                        forgot_password_command=lambda event: self.forgot_password_label_event(),
                                        switch_to_register_frame=lambda event: self.register_label_event())

        self.change_password_frame = ChangePasswordFrame(self.frame, fg_color='transparent', corner_radius=0,
                                                         cancel_button_command=self.cancel_button_event)

        self.register_frame = RegisterFrame(self.frame, fg_color='transparent', corner_radius=0,
                                            switch_to_signin=lambda event: self.sign_in_label_event())

    def get_started_button_event(self):
        self.get_started_frame.grid_forget()
        self.signin_frame.grid(row=0, column=1, sticky='nsew')

    def forgot_password_label_event(self):
        self.signin_frame.grid_forget()
        self.change_password_frame.grid(row=0, column=1, sticky='nsew')

    def cancel_button_event(self):
        self.change_password_frame.grid_forget()
        self.signin_frame.grid(row=0, column=1, sticky='nsew')

    def register_label_event(self):
        self.signin_frame.grid_forget()
        self.register_frame.grid(row=0, column=1, sticky='nsew')

    def sign_in_label_event(self):
        self.register_frame.grid_forget()
        self.signin_frame.grid(row=0, column=1, sticky='nsew')


class GetStartedFrame(ctk.CTkFrame):
    def __init__(self, master, command, **kwargs):
        super().__init__(master, **kwargs)
        self.command = command

        # Configure frame grid layout
        self.columnconfigure(0, weight=1)

        self.subheading_label = ctk.CTkLabel(self, text="Let's get started!",
                                             text_color=text_primary, font=font_subheading)
        self.subheading_label.grid(row=0, column=0, padx=10, pady=(160, 0), sticky='ew')

        self.body_label = ctk.CTkLabel(self, text='If you want to achieve your goals, write them down!',
                                       text_color=text_primary, font=font_body_18)
        self.body_label.grid(row=1, column=0, padx=10, pady=10, sticky='ew')

        self.get_started_button = create_button(self, text='Login', command=self.command)
        self.get_started_button.grid(row=2, column=0, padx=10, pady=10)


class SignInFrame(ctk.CTkFrame):
    def __init__(self, master, forgot_password_command, switch_to_register_frame, **kwargs):
        super().__init__(master, **kwargs)
        self.forgot_pass_command = forgot_password_command
        self.switch_to_command = switch_to_register_frame
        self.show_password = False
        self.acc_signin = AccountSignIn()

        # Configure frame grid layout
        self.columnconfigure(0, weight=1)

        self.subheading_label = ctk.CTkLabel(self, text='Login',
                                             text_color=text_primary, font=font_subheading)
        self.subheading_label.grid(row=0, column=0, padx=10, pady=(75, 0), sticky='ew')

        self.email_error_label = create_error_label(self)
        self.email_error_label.grid(row=1, column=0, padx=20, pady=(16, 0), sticky='w')

        self.email_entry = create_entry_widget(self, text='Enter your Email', valid_icon=email_icon,
                                               validate_command=self.email_validation)
        self.email_entry.grid(row=2, column=0, padx=20, sticky='ew')

        self.password_error_label = create_error_label(self)
        self.password_error_label.grid(row=3, column=0, padx=20, pady=(16, 0), sticky='w')

        self.password_entry = create_entry_widget(self, text='Enter your Password', show='•',
                                                  icon=show_icon, valid_icon=password_icon,
                                                  validate_command=self.password_validation)
        self.password_entry.grid(row=4, column=0, padx=20, sticky='ew')

        self.forgot_pass_label = ctk.CTkLabel(self, text='Forgot password?', text_color=button_hover,
                                              font=font_body_16, cursor='hand2')
        self.forgot_pass_label.grid(row=5, column=0, padx=20, pady=(5, 0), sticky='e')

        self.sign_in_button = create_button(self, text='Sign in', command=self.sign_in_button_event, width=100)
        self.sign_in_button.grid(row=6, column=0, padx=20, pady=15)

        self.switch_to_register = have_account(self, label="Don't have an account?", text='Register')
        self.switch_to_register.grid(row=7, column=0, padx=20, sticky='ew')

        self.password_entry.winfo_children()[2].bind('<Button-1>', lambda event: self.password_toggle())
        self.forgot_pass_label.bind('<Button-1>', self.forgot_pass_command)
        self.switch_to_register.winfo_children()[1].bind('<Button-1>', self.switch_to_command)
        self.sign_in_button.bind('<Return>', lambda event: self.sign_in_button_event())

    def email_validation(self):
        try:
            self.acc_signin.email = self.get_entry_data()[0]
            name = get_name(self.acc_signin.email)
            self.subheading_label.configure(text=f'Welcome Back, {name} !')
            self.email_error_label.configure(text='')
            self.email_entry.winfo_children()[1].configure(image=check_icon)
            return True
        except ValueError as e:
            self.subheading_label.configure(text='Welcome Back!')
            self.email_error_label.configure(text=e)
            self.email_entry.winfo_children()[1].configure(image=error_icon)
            return False

    def password_validation(self):
        try:
            self.acc_signin.password = self.get_entry_data()[1]
            self.password_error_label.configure(text='')
            self.password_entry.winfo_children()[1].configure(image=check_icon)
            return True
        except ValueError as e:
            self.password_error_label.configure(text=e)
            self.password_entry.winfo_children()[1].configure(image=error_icon)
            return False

    def password_toggle(self):
        self.show_password = password_toggle(self.password_entry, self.show_password)

    def get_entry_data(self):
        email = self.email_entry.winfo_children()[0].get().strip()
        password = self.password_entry.winfo_children()[0].get().strip()

        return email, password

    def clear_entry(self):
        self.email_entry.winfo_children()[0].delete(0, 'end')
        self.password_entry.winfo_children()[0].delete(0, 'end')

        self.email_entry.winfo_children()[1].configure(image=profile_icon)
        self.password_entry.winfo_children()[1].configure(image=password_icon)

    def validations(self):
        email_is_valid = self.email_validation()
        password_is_valid = self.password_validation()

        if email_is_valid and password_is_valid:
            return self.acc_signin

    def sign_in_button_event(self):
        creds = self.validations()
        if creds is not None:
            try:
                result = signin_account(creds)
                self.clear_entry()
                if result is not None:
                    response = CTkMessagebox(title='Account Sign In', message='Sign In Successfully', icon='info',
                                             font=font_body_16)
                    if response.get() == 'OK':
                        task_table_name = f'usertasks_{result[0]}'
                        task_frame = TaskFrame(self.master, task_table_name)
                        task_frame.grid(row=0, column=0, columnspan=2, sticky='nsew')
            except EmailNotFound as e:
                CTkMessagebox(title='Account Sign In', message=str(e), icon='cancel', font=font_body_16)
            except WrongPassword as e:
                CTkMessagebox(title='Account Sign In', message=str(e), icon='cancel', font=font_body_16)

        self.subheading_label.configure(text='Welcome Back, User !!')


class ChangePasswordFrame(ctk.CTkFrame):
    def __init__(self, master, cancel_button_command, **kwargs):
        super().__init__(master, **kwargs)
        self.cancel_button_command = cancel_button_command
        self.change_pass = ChangePassword()
        self.old_show_password = False
        self.new_show_password = False

        # Configure frame grid layout
        self.columnconfigure(0, weight=1)

        self.subheading_label = ctk.CTkLabel(self, text='Sorry! You forgot your password!',
                                             text_color=text_primary, font=font_subheading)
        self.subheading_label.grid(row=0, column=0, padx=10, pady=(75, 0), sticky='ew')

        self.email_error_label = create_error_label(self)
        self.email_error_label.grid(row=1, column=0, padx=20, pady=(16, 0), sticky='w')

        self.email_entry = create_entry_widget(self, text='Enter your Email', valid_icon=email_icon,
                                               validate_command=self.email_validation)
        self.email_entry.grid(row=2, column=0, padx=20, sticky='ew')

        self.old_pass_error_label = create_error_label(self)
        self.old_pass_error_label.grid(row=3, column=0, padx=20, pady=(16, 0), sticky='w')

        self.old_password_entry = create_entry_widget(self, text='Enter Old Password', show='•', icon=show_icon,
                                                      valid_icon=password_icon,
                                                      validate_command=self.old_password_validation)
        self.old_password_entry.grid(row=4, column=0, padx=20, sticky='ew')

        self.new_pass_error_label = create_error_label(self)
        self.new_pass_error_label.grid(row=5, column=0, padx=20, pady=(16, 0), sticky='w')

        self.new_password_entry = create_entry_widget(self, text='Enter New Password', show='•', icon=show_icon,
                                                      valid_icon=password_icon,
                                                      validate_command=self.new_password_validation)
        self.new_password_entry.grid(row=6, column=0, padx=20, sticky='ew')

        self.cancel_button = create_secondary_button(self, text='Cancel', command=self.cancel_button_command, width=80)
        self.cancel_button.grid(row=7, column=0, padx=20, pady=20, sticky='w')

        self.change_pass_button = create_button(self, text='Change Password', command=self.change_pass_button_event)
        self.change_pass_button.grid(row=7, column=0, padx=20, pady=20, sticky='e')

        # Event Binding
        self.old_password_entry.winfo_children()[2].bind('<Button-1>', lambda event: self.old_password_toggle())
        self.new_password_entry.winfo_children()[2].bind('<Button-1>', lambda event: self.new_password_toggle())
        self.change_pass_button.bind('<Return>', lambda event: self.change_pass_button_event())

    def email_validation(self):
        try:
            self.change_pass.email = self.get_entry_data()[0]
            self.email_error_label.configure(text='')
            self.email_entry.winfo_children()[1].configure(image=check_icon)
            return True
        except ValueError as e:
            self.email_error_label.configure(text=e)
            self.email_entry.winfo_children()[1].configure(image=error_icon)
            return False

    def old_password_validation(self):
        try:
            self.change_pass.old_password = self.get_entry_data()[1]
            self.old_pass_error_label.configure(text='')
            self.old_password_entry.winfo_children()[1].configure(image=check_icon)
            return True
        except ValueError as e:
            self.old_pass_error_label.configure(text=e)
            self.old_password_entry.winfo_children()[1].configure(image=error_icon)
            return False

    def new_password_validation(self):
        try:
            self.change_pass.new_password = self.get_entry_data()[2]
            self.new_pass_error_label.configure(text='')
            self.new_password_entry.winfo_children()[1].configure(image=check_icon)
            return True
        except ValueError as e:
            self.new_pass_error_label.configure(text=e)
            self.new_password_entry.winfo_children()[1].configure(image=error_icon)
            return False

    def old_password_toggle(self):
        self.old_show_password = password_toggle(self.old_password_entry, self.old_show_password)

    def new_password_toggle(self):
        self.new_show_password = password_toggle(self.new_password_entry, self.new_show_password)

    def get_entry_data(self):
        email = self.email_entry.winfo_children()[0].get().strip()
        old_password = self.old_password_entry.winfo_children()[0].get().strip()
        new_password = self.new_password_entry.winfo_children()[0].get().strip()
        return email, old_password, new_password

    def clear_entry(self):
        self.email_entry.winfo_children()[0].delete(0, 'end')
        self.old_password_entry.winfo_children()[0].delete(0, 'end')
        self.new_password_entry.winfo_children()[0].delete(0, 'end')

        self.email_entry.winfo_children()[1].configure(image=email_icon)
        self.old_password_entry.winfo_children()[1].configure(image=password_icon)
        self.new_password_entry.winfo_children()[1].configure(image=password_icon)

    def validations(self):
        email_is_valid = self.email_validation()
        old_pass_is_valid = self.old_password_validation()
        new_pass_is_valid = self.new_password_validation()

        if email_is_valid and old_pass_is_valid and new_pass_is_valid:
            return self.change_pass

    def change_pass_button_event(self):
        creds = self.validations()
        try:
            if creds is not None:
                change_password(creds)
                self.clear_entry()
                CTkMessagebox(title='Change Password', message='Password Changed Successfully', font=font_body_16)
        except EmailNotFound as e:
            CTkMessagebox(title='Change Password', message=str(e), icon='cancel', font=font_body_16)
        except WrongPassword as e:
            CTkMessagebox(title='Change Password', message=str(e), icon='cancel', font=font_body_16)


class RegisterFrame(ctk.CTkFrame):
    def __init__(self, master, switch_to_signin, **kwargs):
        super().__init__(master, **kwargs)
        self.acc_registration = AccountRegistration()
        self.switch_to_command = switch_to_signin
        self.show_password = False

        # Configure frame grid layout
        self.columnconfigure(0, weight=1)

        self.subheading_label = ctk.CTkLabel(self, text='Welcome !',
                                             text_color=text_primary, font=font_subheading)
        self.subheading_label.grid(row=0, column=0, padx=10, pady=(75, 0), sticky='ew')

        self.fullname_error_label = create_error_label(self)
        self.fullname_error_label.grid(row=1, column=0, padx=20, pady=(16, 0), sticky='w')

        self.fullname_entry = create_entry_widget(self, text='Enter your Fullname', valid_icon=profile_icon,
                                                  validate_command=self.name_validation)
        self.fullname_entry.grid(row=2, column=0, padx=20, sticky='ew')

        self.email_error_label = create_error_label(self)
        self.email_error_label.grid(row=3, column=0, padx=20, pady=(14, 0), sticky='w')

        self.email_entry = create_entry_widget(self, text='Enter your Email', valid_icon=email_icon,
                                               validate_command=self.email_validation)
        self.email_entry.grid(row=4, column=0, padx=20, sticky='ew')

        self.password_error_label = create_error_label(self)
        self.password_error_label.grid(row=5, column=0, padx=20, pady=(14, 0), sticky='w')

        self.password_entry = create_entry_widget(self, text='Enter your Password', show='•', icon=show_icon,
                                                  valid_icon=password_icon,
                                                  validate_command=self.password_validation)
        self.password_entry.grid(row=6, column=0, padx=20, sticky='ew')

        self.register_button = create_button(self, text='Register', command=self.register_button_event, width=100, )
        self.register_button.grid(row=7, column=0, padx=20, pady=20)

        self.switch_to_signin = have_account(self, label='Already have an account?', text='Sign in')
        self.switch_to_signin.grid(row=8, column=0, padx=20, sticky='ew')

        # Event Binding
        self.password_entry.winfo_children()[2].bind('<Button-1>', lambda event: self.password_toggle())
        self.switch_to_signin.winfo_children()[1].bind('<Button-1>', self.switch_to_command)
        self.register_button.bind('<Return>', lambda event: self.register_button_event())

    def name_validation(self):
        try:
            self.acc_registration.fullname = self.get_entry_data()[0]
            self.fullname_error_label.configure(text='')
            self.fullname_entry.winfo_children()[1].configure(image=check_icon)
            return True
        except ValueError as e:
            self.fullname_error_label.configure(text=e)
            self.fullname_entry.winfo_children()[1].configure(image=error_icon)
            return False

    def email_validation(self):
        try:
            self.acc_registration.email = self.get_entry_data()[1]
            self.email_error_label.configure(text='')
            self.email_entry.winfo_children()[1].configure(image=check_icon)
            return True
        except ValueError as e:
            self.email_error_label.configure(text=e)
            self.email_entry.winfo_children()[1].configure(image=error_icon)
            return False

    def password_validation(self):
        try:
            self.acc_registration.password = self.get_entry_data()[2]
            self.password_error_label.configure(text='')
            self.password_entry.winfo_children()[1].configure(image=check_icon)
            return True
        except ValueError as e:
            self.password_error_label.configure(text=e)
            self.password_entry.winfo_children()[1].configure(image=error_icon)
            return False

    def password_toggle(self):
        self.show_password = password_toggle(self.password_entry, self.show_password)

    def get_entry_data(self):
        fullname = self.fullname_entry.winfo_children()[0].get().strip().title()
        email = self.email_entry.winfo_children()[0].get().strip()
        password = self.password_entry.winfo_children()[0].get().strip()

        return fullname, email, password

    def clear_entry(self):
        self.fullname_entry.winfo_children()[0].delete(0, 'end')
        self.email_entry.winfo_children()[0].delete(0, 'end')
        self.password_entry.winfo_children()[0].delete(0, 'end')

        self.fullname_entry.winfo_children()[1].configure(image=profile_icon)
        self.email_entry.winfo_children()[1].configure(image=email_icon)
        self.password_entry.winfo_children()[1].configure(image=password_icon)

    def validations(self):
        fullname_is_valid = self.name_validation()
        email_is_valid = self.email_validation()
        password_is_valid = self.password_validation()

        if fullname_is_valid and email_is_valid and password_is_valid:
            return self.acc_registration

    def register_button_event(self):
        creds = self.validations()
        try:
            if creds is not None:
                register_account(creds)
                self.clear_entry()
                CTkMessagebox(title='Account Registration', message='Account Registered Successfully',
                              icon='info', font=font_body_16)
        except AccountExistsError as e:
            CTkMessagebox(title='Account Registration', message=str(e), icon='cancel', font=font_body_16)


class TaskFrame(ctk.CTkFrame):
    def __init__(self, master, table_name, **kwargs):
        super().__init__(master, **kwargs)
        self.configure(fg_color='transparent', corner_radius=0)
        self.table_name = table_name
        self.toplevel_window = None
        self.frame_list = []

        # Configure frame grid layout
        self.columnconfigure(0, weight=1, uniform='a')
        self.columnconfigure(1, weight=1, uniform='a')
        self.rowconfigure(3, weight=1)

        self.header_frame = ctk.CTkFrame(self, fg_color=button_hover, corner_radius=0)
        self.header_frame.grid(row=0, column=0, columnspan=2, sticky='nsew')
        self.header_frame.columnconfigure(0, weight=1)

        self.title_label = ctk.CTkLabel(self.header_frame, text='What to do?', text_color=text_secondary,
                                        font=font_heading)
        self.title_label.grid(row=0, column=0, padx=20, pady=15, sticky='w')

        self.sign_out_label = ctk.CTkLabel(self.header_frame, text='Sign out', text_color=text_secondary,
                                           font=font_body_16, cursor='hand2')
        self.sign_out_label.grid(row=0, column=0, padx=20, pady=15, sticky='e')

        self.todo_banner = create_banner(self, banner_label='To Do', color=todo_banner_color)
        self.todo_banner.grid(row=1, column=0, padx=(20, 0), pady=(40, 0), sticky='e')

        self.done_banner = create_banner(self, banner_label='Done', color=done_banner_color)
        self.done_banner.grid(row=1, column=1, padx=20, pady=(40, 0), sticky='w')

        self.new_task_button = create_button(self, text='New Task', command=self.new_task_button_event, width=100)
        self.new_task_button.grid(row=2, column=1, padx=60, pady=(20, 0), sticky='e')

        self.task_scrollable_frame = ctk.CTkScrollableFrame(self, corner_radius=0, fg_color='transparent')
        self.task_scrollable_frame.grid(row=3, column=0, columnspan=2, pady=10, sticky='nsew')
        self.task_scrollable_frame.columnconfigure(0, weight=1)

        self.sign_out_label.bind('<Button-1>', lambda event: self.destroy())

        self.add_task()

    def new_task_button_event(self):
        if self.toplevel_window is None or not self.toplevel_window.winfo_exists():
            self.toplevel_window = AddTaskWindow(self, table_name=self.table_name, add_task=self.add_task)
            self.toplevel_window.attributes('-topmost', True)
        else:
            self.toplevel_window.focus()

    def add_task(self):
        self.frame_list.clear()

        for widget in self.task_scrollable_frame.winfo_children():
            widget.destroy()

        all_available_task = get_all_task(table_name=self.table_name, )
        for task in all_available_task:
            self.add_task_frame(task[0], task[1])

    def add_task_frame(self, task_name, task_status):
        task_var = StringVar(value=task_status)
        frame = ctk.CTkFrame(self.task_scrollable_frame, fg_color=widget_color)
        frame.columnconfigure(0, weight=1)
        frame.grid(row=len(self.frame_list), column=0, padx=40, pady=(0, 10), sticky='ew')

        task = ctk.CTkCheckBox(frame, text=task_name, text_color=text_primary, font=font_body_16,
                               variable=task_var, onvalue='Done', offvalue='To Do',
                               command=lambda: self.checkbox_event(task))
        task.grid(row=0, column=0, padx=10, pady=10, sticky='w')

        delete_button = ctk.CTkLabel(frame, text='', image=delete_icon, cursor='hand2')
        delete_button.grid(row=0, column=1, padx=20, )

        if task_var.get() == 'Done':
            task.configure(font=font_body_18_overstrike, text_color=text_tertiary)
        else:
            pass

        # Event Binding
        delete_button.bind('<Button-1>', lambda event: self.delete_button_event(frame))
        self.frame_list.append({'frame': frame, 'task': task})
        self.update_scrollable_frame()

    def delete_button_event(self, item_frame):
        for frame in self.frame_list:
            if frame['frame'] == item_frame:
                delete_task(table_name=self.table_name, task=frame['task'].cget('text'))
                item_frame.destroy()
                self.frame_list.remove(frame)
                self.update_scrollable_frame()

                break

    def checkbox_event(self, widget):
        for frame in self.frame_list:
            if frame['task'] == widget and frame['task'].get() == 'Done':
                frame['task'].configure(font=font_body_18_overstrike, text_color=text_tertiary)
                update_status(table_name=self.table_name, status=frame['task'].get(),
                              task=frame['task'].cget('text'))
                break
            elif frame['task'] == widget and frame['task'].get() == 'To Do':
                frame['task'].configure(font=font_body_16, text_color=text_primary)
                update_status(table_name=self.table_name, status=frame['task'].get(),
                              task=frame['task'].cget('text'))
                break
        self.update_banner()

    def update_scrollable_frame(self):
        for i, frame in enumerate(reversed(self.frame_list)):
            frame['frame'].grid(row=i, column=0, padx=40, pady=(0, 10), sticky='ew')
        self.update_banner()

    def update_banner(self):
        todo_count, done_count = update_count(table_name=self.table_name)
        self.todo_banner.winfo_children()[1].configure(text=todo_count)
        self.done_banner.winfo_children()[1].configure(text=done_count)


class AddTaskWindow(ctk.CTkToplevel):
    def __init__(self, master, table_name, add_task, **kwargs):
        super().__init__(master, **kwargs)

        self.task_obj = TaskCreation()
        self.table_name = table_name
        self.add_task = add_task

        toplevel_width = 600
        toplevel_height = 450

        main_window_width = master.winfo_width()
        main_window_height = master.winfo_height()

        x = (main_window_width - toplevel_width) // 2
        y = (main_window_height - toplevel_height) // 2

        self.geometry(f'{toplevel_width}x{toplevel_height}+{x}+{y}')
        self.resizable(False, False)
        self.title('Task Window')
        self.configure(fg_color='#cfb0ce', borderwidth=2, relief=SOLID)
        # self.overrideredirect(True)
        # Configure window grid layout
        self.columnconfigure(0, weight=1,)

        self.bg_image = ctk.CTkImage(Image.open(os.path.join(asset_path, 'add-task.png')),
                                     size=(250, 250))
        self.bg_image_label = ctk.CTkLabel(self, text='', image=self.bg_image)
        self.bg_image_label.grid(row=0, column=0, pady=(10, 0), sticky='nsew')

        self.task_entry = create_entry_widget(self, text='Create Task', )
        self.task_entry.grid(row=1, column=0, padx=50, pady=(0, 5), sticky='nsew')

        self.save_button = create_button(self, text='Save', command=self.save_button_event, width=100)
        self.save_button.grid(row=2, column=0, pady=5)

        # Event Binding
        self.task_entry.bind('<Return>', lambda event: self.save_button_event())

    def save_button_event(self):
        try:
            self.task_obj.task = self.task_entry.winfo_children()[0].get().capitalize()
            add_new_task(table_name=self.table_name, task=self.task_obj.task)
            self.add_task()
            self.destroy()
        except ValueError:
            pass


if __name__ == '__main__':
    app = App()
    app.mainloop()
