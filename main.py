import tkinter as tk
from tkinter import messagebox, simpledialog
import hashlib
import os
import datetime


class MedicalCentreApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Medical Centre Management System")
        self.root.geometry("600x500")

        self.current_frame = None
        self.current_role = None
        self.show_initial_screen()

    def show_initial_screen(self):
        self.clear_frame()
        self.current_frame = tk.Frame(self.root)
        self.current_frame.pack(fill="both", expand=True)

        admin_login_button = tk.Button(self.current_frame, text="Admin Login", command=self.admin_login)
        admin_login_button.pack(pady=(20, 10))

        doctor_login_button = tk.Button(self.current_frame, text="Doctor Login", command=self.doctor_login)
        doctor_login_button.pack(pady=(10, 10))

        super_admin_login_button = tk.Button(self.current_frame, text="Super Admin Login", command=self.super_admin_login)
        super_admin_login_button.pack(pady=(10, 20))

    def admin_login(self):
        self.current_role = "Admin"
        self.show_login_screen()

    def doctor_login(self):
        self.current_role = "Doctor"
        self.show_login_screen()

    def super_admin_login(self):
        self.current_role = "Super Admin"
        self.show_login_screen()


    def show_login_screen(self):
        self.clear_frame()
        self.current_frame = tk.Frame(self.root)
        self.current_frame.pack(fill="both", expand=True)

        tk.Label(self.current_frame, text=f"{self.current_role} Username:").pack(pady=(10, 0))
        self.username_entry = tk.Entry(self.current_frame)
        self.username_entry.pack(pady=(0, 10))
        self.username_entry.focus()

        tk.Label(self.current_frame, text=f"{self.current_role} Password:").pack()
        self.password_entry = tk.Entry(self.current_frame, show="*")
        self.password_entry.pack(pady=(0, 10))

        login_button = tk.Button(self.current_frame, text="Login", command=self.authenticate_user)
        login_button.pack(pady=(10, 10))

        back_button = tk.Button(self.current_frame, text="Back to Login Options", command=self.show_initial_screen)
        back_button.pack(pady=(10, 10))

    def clear_frame(self):
        if self.current_frame is not None:
            self.current_frame.destroy()
            self.current_frame = None

    def authenticate_user(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        hashed_password = self.hash_password(password)

        if self.check_credentials(self.current_role.lower(), username, hashed_password):
            messagebox.showinfo("Login Success", f"Successfully logged in as {self.current_role}")
            self.clear_frame()
            if self.current_role.lower() == "admin":
                self.show_admin_screen()
            elif self.current_role.lower() == "doctor":
                self.show_doctor_screen(username)
            elif self.current_role.lower() == "super admin":
                self.show_super_admin_screen()
            else:
                print(f"Logged in as {self.current_role}, but not admin or doctor")
        else:
            messagebox.showerror("Login Failed", "Invalid username or password")

    def hash_password(self, password):
        return hashlib.sha256(password.encode()).hexdigest()

    def check_credentials(self, role, username, hashed_password):
        section = role + "_password"
        credentials = self.get_section_data(section)
        for credential in credentials:
            if credential.startswith(f"{section}:"):
                continue
            stored_username, stored_password = credential.split(',')
            if username == stored_username.strip() and hashed_password == stored_password.strip():
                return True
        return False

    def show_admin_screen(self):
        self.clear_frame()
        self.current_frame = tk.Frame(self.root)
        self.current_frame.pack(fill="both", expand=True)

        doctor_management_button = tk.Button(self.current_frame, text="Doctor Management", command=self.doctor_management)
        doctor_management_button.pack(pady=(10, 5))

        view_patient_record_button = tk.Button(self.current_frame, text="View Patient Record", command=self.view_patient_record)
        view_patient_record_button.pack(pady=(5, 5))

        assign_patient_button = tk.Button(self.current_frame, text="Assign Patient to Doctor", command=self.assign_patient)
        assign_patient_button.pack(pady=(5, 10))
        discharge_patient_button = tk.Button(self.current_frame, text="Discharge Patient",command=self.discharge_patient)
        discharge_patient_button.pack(pady=(5, 10))

        view_treated_patients_button = tk.Button(self.current_frame, text="View Treated Patients", command=self.view_treated_patients)
        view_treated_patients_button.pack(pady=(5, 10))

        update_admin_info_button = tk.Button(self.current_frame, text="Update Admin Info", command=self.update_admin_info)
        update_admin_info_button.pack(pady=(5, 10))

        enroll_patient_button = tk.Button(self.current_frame, text="Enroll Patients", command=self.enroll_patient)
        enroll_patient_button.pack(pady=(5, 5))

        book_appointment_button = tk.Button(self.current_frame, text="Book Appointment", command=self.book_appointment)
        book_appointment_button.pack(pady=(5, 5))

        view_assigned_doctor_button = tk.Button(self.current_frame, text="View Assigned Doctor",
                                                command=self.view_assigned_doctor)
        view_assigned_doctor_button.pack(pady=(5, 5))

        management_report_button = tk.Button(self.current_frame, text="Create management report",
                                             command=self.management_report)
        management_report_button.pack(pady=(5, 5))

        logout_button = tk.Button(self.current_frame, text="Logout", command=self.show_initial_screen)
        logout_button.pack(pady=(10, 10))

    def show_super_admin_screen(self):
        self.clear_frame()
        self.current_frame = tk.Frame(self.root)
        self.current_frame.pack(fill="both", expand=True)

        add_admin_button = tk.Button(self.current_frame, text="Add Admin", command=self.add_admin)
        add_admin_button.pack(pady=(5, 10))

        delete_admin_button = tk.Button(self.current_frame, text="Delete Admin", command=self.delete_admin)
        delete_admin_button.pack(pady=(5, 10))

        view_admins_button = tk.Button(self.current_frame, text="View Admins", command=self.view_admins)
        view_admins_button.pack(pady=(5, 10))

        logout_button = tk.Button(self.current_frame, text="Logout", command=self.show_initial_screen)
        logout_button.pack(pady=(10, 10))

    def add_admin(self):
        new_admin_username = tk.simpledialog.askstring("Add Admin", "Enter New Admin's Username:")
        if not new_admin_username:
            return

        new_admin_password = tk.simpledialog.askstring("Add Admin", "Enter New Admin's Password:")
        if not new_admin_password:
            return

        admin_credentials = self.get_section_data("admin_password")

        # Check if the admin username already exists
        if any(new_admin_username in cred for cred in admin_credentials):
            messagebox.showerror("Error", f"Admin '{new_admin_username}' already exists.")
        else:
            admin_credentials.append(f"{new_admin_username}, {hashlib.sha256(new_admin_password.encode()).hexdigest()}")
            self.write_section_data("admin_password", admin_credentials)
            messagebox.showinfo("Success", f"Admin '{new_admin_username}' added successfully.")

    def delete_admin(self):
        admin_username = tk.simpledialog.askstring("Delete Admin", "Enter Admin's Username to delete:")
        if not admin_username:
            return

        admin_credentials = self.get_section_data("admin_password")

        # Check if the admin username exists and remove it along with its password
        updated_credentials = [cred for cred in admin_credentials if not cred.startswith(admin_username + ",")]

        if len(admin_credentials) == len(updated_credentials):
            messagebox.showerror("Error", f"Admin '{admin_username}' not found.")
        else:
            self.write_section_data("admin_password", updated_credentials)
            messagebox.showinfo("Success", f"Admin '{admin_username}' deleted successfully.")

    def view_admins(self):
        admin_credentials = self.get_section_data("admin_password")

        # Extract and display the first names of the admins
        admin_first_names = [cred.split(',')[0].split()[0] for cred in admin_credentials if cred]
        display_text = "Admin First Names:\n" + "\n".join(
            admin_first_names) if admin_first_names else "No admins found."

        messagebox.showinfo("Admins", display_text)
    def doctor_management(self):
        self.clear_frame()
        self.current_frame = tk.Frame(self.root)
        self.current_frame.pack(fill="both", expand=True)

        management_buttons_frame = tk.Frame(self.current_frame)
        management_buttons_frame.pack(expand=True)

        tk.Button(management_buttons_frame, text="Register Doctor", command=self.register_doctor).pack(pady=(5, 5))
        tk.Button(management_buttons_frame, text="View Doctor", command=self.view_doctor).pack(pady=(5, 5))
        tk.Button(management_buttons_frame, text="Update Doctor", command=self.update_doctor).pack(pady=(5, 5))
        tk.Button(management_buttons_frame, text="Delete Doctor", command=self.delete_doctor).pack(pady=(5, 5))

        back_to_admin_button = tk.Button(management_buttons_frame, text="Back to Admin", command=self.show_admin_screen)
        back_to_admin_button.pack(pady=(10, 10))

    def register_doctor(self):
        doctor_name = tk.simpledialog.askstring("Register Doctor", "Enter Doctor's Name:")
        if not doctor_name:
            return

        doctor_password = tk.simpledialog.askstring("Register Doctor", "Enter Doctor's Password:", show="*")
        if not doctor_password:
            return

        # Check if the doctor already exists
        doctor_credentials = self.get_section_data("doctor_password")
        if any(doctor_name in cred for cred in doctor_credentials):
            messagebox.showerror("Error", f"Doctor '{doctor_name}' already exists.")
            return

        # Add the doctor's credentials to the 'doctor_password' section
        hashed_password = hashlib.sha256(doctor_password.encode()).hexdigest()
        doctor_credentials.append(f"{doctor_name}, {hashed_password}")
        self.write_section_data("doctor_password", doctor_credentials)

        messagebox.showinfo("Success", f"Doctor '{doctor_name}' registered successfully.")

    def view_doctor(self):
        doctor_credentials = self.get_section_data("doctor_password")
        doctor_names = [cred.split(',')[0] for cred in doctor_credentials]
        doctor_info = "\n".join(doctor_names) if doctor_names else "No doctors registered yet."
        messagebox.showinfo("Doctors List", doctor_info)

    def update_doctor(self):
        old_name = tk.simpledialog.askstring("Update Doctor", "Enter current Doctor's Name:")
        if not old_name:
            return

        new_name = tk.simpledialog.askstring("Update Doctor", "Enter new Doctor's Name:")
        if not new_name:
            return

        doctor_credentials = self.get_section_data("doctor_password")
        updated_credentials = []
        found = False

        for cred in doctor_credentials:
            name, password = cred.split(',')
            if name == old_name:
                updated_credentials.append(f"{new_name}, {password}")
                found = True
            else:
                updated_credentials.append(cred)

        if found:
            self.write_section_data("doctor_password", updated_credentials)
            messagebox.showinfo("Success", "Doctor updated successfully.")
        else:
            messagebox.showerror("Error", "Doctor not found.")

    def delete_doctor(self):
        doctor_name = tk.simpledialog.askstring("Delete Doctor", "Enter Doctor's Name to delete:")
        if not doctor_name:
            return

        doctor_credentials = self.get_section_data("doctor_password")
        updated_credentials = [cred for cred in doctor_credentials if not cred.startswith(doctor_name + ",")]

        if len(doctor_credentials) == len(updated_credentials):
            messagebox.showerror("Error", f"Doctor '{doctor_name}' not found.")
        else:
            self.write_section_data("doctor_password", updated_credentials)
            messagebox.showinfo("Success", f"Doctor '{doctor_name}' deleted successfully.")

    def view_patient_record(self):
        patient_name = tk.simpledialog.askstring("View Patient Record", "Enter Patient's Name:")
        if not patient_name:
            return

        patient_records = self.get_section_data("patient_records")
        record_found = False
        for record in patient_records:
            if f"Patient Name - {patient_name}" in record:
                messagebox.showinfo("Patient Record", record)
                record_found = True
                break

        if not record_found:
            messagebox.showerror("Error", f"No record found for patient '{patient_name}'.")

    def assign_patient(self):
        patient_name = tk.simpledialog.askstring("Assign Patient", "Enter Patient's Name:")
        doctor_name = tk.simpledialog.askstring("Assign Patient", "Enter Doctor's Name to assign:")
        if not patient_name or not doctor_name:
            return

        # Extracting doctor names from the 'doctor_password' data
        doctors = self.get_section_data("doctor_password")
        doctor_names = [d.split(',')[0].strip() for d in doctors]

        if doctor_name not in doctor_names:
            messagebox.showerror("Error", "Doctor not found.")
            return

        # Extracting patient names from the 'patients' data
        patients = self.get_section_data("patients")
        patient_names = [p.split(' - ')[0].strip() for p in patients]

        if patient_name not in patient_names:
            messagebox.showerror("Error", "Patient not found.")
            return

        # Assigning the patient to the doctor
        assignments = self.get_section_data("patient_assignments")
        assignments.append(f"Patient: {patient_name} - Doctor: {doctor_name}," )
        self.write_section_data("patient_assignments", assignments)
        messagebox.showinfo("Success", f"Patient '{patient_name}' assigned to doctor '{doctor_name}' successfully.")




    def show_doctor_screen(self, username):
        self.clear_frame()
        self.current_username = username  # Store the current doctor's username
        self.current_frame = tk.Frame(self.root)
        self.current_frame.pack(fill="both", expand=True)

        view_patient_records_button = tk.Button(self.current_frame, text="View Patient Records",
                                                command=self.view_patient_record)
        view_patient_records_button.pack(pady=(10, 5))

        view_appointments_button = tk.Button(self.current_frame, text="View Appointments",
                                             command=self.view_appointments)
        view_appointments_button.pack(pady=(5, 5))

        Approve_appointment_status_button = tk.Button(self.current_frame, text="Approve Appointment Status",
                                                     command=self.approve_appointment_status)
        Approve_appointment_status_button.pack(pady=(5, 10))

        logout_button = tk.Button(self.current_frame, text="Logout", command=self.show_initial_screen)
        logout_button.pack(pady=(10, 10))

    def view_appointments(self):
        if self.current_role.lower() == "doctor":
            appointments = self.get_section_data("appointments")
            print(self.current_username)
            doctor_appointments = [appointment for appointment in appointments if
                                   f"Doctor: {self.current_username}" in appointment]
            appointment_info = "\n".join(
                doctor_appointments) if doctor_appointments else "No appointments for this doctor."
            messagebox.showinfo("Appointments", appointment_info)

    def enroll_patient(self):
        patient_name = tk.simpledialog.askstring("Enroll Patient", "Enter Patient's Name:")
        illness_name = tk.simpledialog.askstring("Enroll Patient", "Enter Illness:")
        patient_surname = tk.simpledialog.askstring("Enroll Patient", "Enter Patient's Surname:")
        patient_age = tk.simpledialog.askstring("Enroll Patient", "Enter Patient's Age:")
        if patient_name:
            if illness_name:
                patients = self.get_section_data("patients")
                patient_records = self.get_section_data("patient_records")
                patients.append(patient_name + " - Illness: " + illness_name + ",")
                patient_records.append("Patient Name - " + patient_name + " Age - " + patient_age +",")
                self.write_section_data("patients", patients)
                self.write_section_data("patient_records", patient_records)
                messagebox.showinfo("Success", "Patient enrolled successfully.")
        if patient_surname:
            families = self.get_section_data("families")
            updated_families = []
            family_found = False

            for family in families:
                if patient_surname == family.split(" -")[0]:
                    family += f", {patient_name}"
                    family_found = True
                updated_families.append(family)

            # If the family is not found, add a new entry
            if not family_found:
                new_family_entry = f"{patient_surname} - {patient_name}"
                updated_families.append(new_family_entry)

            self.write_section_data("families", updated_families)

            if family_found:
                messagebox.showinfo("Success",
                                    f"Patient '{patient_name}' added to the family '{patient_surname}' successfully.")
            else:
                messagebox.showinfo("Success", f"New family '{patient_surname}' created with patient '{patient_name}'.")

    def book_appointment(self):
        doctor_name = tk.simpledialog.askstring("Book Appointment", "Enter Doctor's Name:")
        doctors = self.get_section_data("doctor_password")
        doctor_names = [d.split(',')[0].strip() for d in doctors]  # Extract doctor names
        if doctor_name not in doctor_names:
            messagebox.showerror("Error", "Doctor not found.")
            return

        patient_name = tk.simpledialog.askstring("Book Appointment", "Enter Patient's Name:")
        patients = self.get_section_data("patients")
        patient_names = [p.split(' - ')[0].strip() for p in patients]  # Extract patient names
        if patient_name not in patient_names:
            messagebox.showerror("Error", "Patient not found.")
            return

        appointment_date_str = tk.simpledialog.askstring("Book Appointment", "Enter Appointment Date (YYYY-MM-DD):")
        if not doctor_name or not patient_name or not appointment_date_str:
            messagebox.showerror("Error", "All fields are required.")
            return

        # Validate appointment date
        try:
            appointment_date = datetime.datetime.strptime(appointment_date_str, '%Y-%m-%d').date()
            if appointment_date < datetime.date.today():
                messagebox.showerror("Error", "Appointment date cannot be in the past.")
                return
        except ValueError:
            messagebox.showerror("Error", "Invalid date format. Please enter a date in YYYY-MM-DD format.")
            return

        appointments = self.get_section_data("appointments")
        appointments.append(
            f"Doctor: {doctor_name} - Patient: {patient_name} - Date: {appointment_date_str} - Status: pending,")
        self.write_section_data("appointments", appointments)
        messagebox.showinfo("Success", "Appointment booked successfully.")

    def view_assigned_doctor(self):
        patient_name = tk.simpledialog.askstring("View Assigned Doctor", "Enter Patient's Name:")
        if patient_name:
            assignments = self.get_section_data("patient_assignments")
            assigned_doctor = next(
                (line.split('-')[1].strip() for line in assignments if line.startswith(f"Patient: {patient_name}")),
                None)
            if assigned_doctor:
                messagebox.showinfo("Assigned Doctor", f"The assigned doctor for {patient_name} is {assigned_doctor}.")
            else:
                messagebox.showerror("Error", f"No assigned doctor found for patient '{patient_name}'.")

    def approve_appointment_status(self):
        patient_name = simpledialog.askstring("Approve Appointment Status", "Enter Patient's Name:")
        appointment_date = simpledialog.askstring("Approve Appointment Status", "Enter Appointment Date (YYYY-MM-DD):")
        if not patient_name or not appointment_date:
            return

        appointments = self.get_section_data("appointments")
        updated_appointments = []
        for appointment in appointments:
            if f"Patient: {patient_name}" in appointment and f"Date: {appointment_date}" in appointment:
                updated_appointments.append(appointment.replace("pending", "approved"))
            else:
                updated_appointments.append(appointment)
        self.write_section_data("appointments", updated_appointments)
        messagebox.showinfo("Success", f"Appointment status updated for {patient_name} on {appointment_date}.")

    def discharge_patient(self):
        patient_name = tk.simpledialog.askstring("Discharge Patient", "Enter Patient's Name to discharge:")
        if not patient_name:
            return

        # Extract patient names from the 'patients' data
        patients = self.get_section_data("patients")
        patient_names = [p.split(' - ')[0].strip() for p in patients]

        if patient_name in patient_names:
            # Remove the patient from the list of patients
            updated_patients = [p for p in patients if not p.startswith(patient_name + " - ")]
            self.write_section_data("patients", updated_patients)

            # Add the patient to the treated patient list
            treated_patients = self.get_section_data("treated_patients")
            treated_patients.append(patient_name + ",")
            self.write_section_data("treated_patients", treated_patients)

            # Remove the patient's appointments
            appointments = self.get_section_data("appointments")
            updated_appointments = [a for a in appointments if not a.startswith(f"Patient: {patient_name}")]
            self.write_section_data("appointments", updated_appointments)

            messagebox.showinfo("Success",
                                f"Patient '{patient_name}' discharged successfully and added to Treated Patients.")
        else:
            messagebox.showerror("Error", f"Patient '{patient_name}' not found.")

    def view_treated_patients(self):
        treated_patients = self.get_section_data("treated_patients")
        treated_patients_info = "\n".join(treated_patients) if treated_patients else "No treated patients found."
        messagebox.showinfo("Treated Patients", treated_patients_info)

    def update_admin_info(self):
        new_name = tk.simpledialog.askstring("Update Admin Info", "Enter new name:")
        new_address = tk.simpledialog.askstring("Update Admin Info", "Enter new address:")
        if new_name and new_address:
            admin_info = [f"Name: {new_name}", f"Address: {new_address}"]
            self.write_section_data("admin_info", admin_info)
            messagebox.showinfo("Success", "Admin information updated successfully.")

    def get_section_data(self, section_name, file_path="data.txt"):
        data = []
        in_section = False
        try:
            with open(file_path, 'r') as file:
                for line in file:
                    if line.strip() == f"{section_name}:":
                        in_section = True
                    elif line.strip().endswith(":") and in_section:
                        break
                    elif in_section:
                        data.append(line.strip())
            return data
        except FileNotFoundError:
            print(f"File not found: {file_path}")
            return []

    def write_section_data(self, section_name, new_data, file_path="data.txt"):
        entire_data = {}
        current_section = None

        # Read the entire file and categorize data by section
        try:
            with open(file_path, 'r') as file:
                for line in file:
                    if line.strip().endswith(":"):
                        current_section = line.strip()
                        entire_data[current_section] = []
                    elif current_section:
                        entire_data[current_section].append(line.strip())

        except FileNotFoundError:
            print(f"File not found: {file_path}")
            return

        # Update the section
        entire_data[f"{section_name}:"] = new_data

        # Write back the entire data
        with open(file_path, 'w') as file:
            for section, data in entire_data.items():
                file.write(section + "\n")
                for item in data:
                    file.write(f"  {item}\n")

        print(f"Updated section {section_name} in {file_path}")

    def management_report(self):
        doctors = self.get_section_data("doctor_password")

        if not doctors:
            messagebox.showerror("Error", "No doctors registered in the system.")
            return

        total_patients_per_doctor = self.calculate_total_patients_per_doctor(doctors)
        total_appointments_per_doctor = self.calculate_total_appointments_per_doctor(doctors)
        total_patients_by_illness_type = self.calculate_total_patients_by_illness_type()

        report = self.format_management_report(
            doctors,
            total_patients_per_doctor,
            total_appointments_per_doctor,
            total_patients_by_illness_type
        )

        messagebox.showinfo("Management Report", report)

    def calculate_total_patients_per_doctor(self, doctors):
        total_patients_per_doctor = {}
        for doctor in doctors:
            patients_assigned = self.get_patients_assigned_to_doctor(doctor)
            total_patients_per_doctor[doctor] = len(patients_assigned)
        return total_patients_per_doctor

    def calculate_total_appointments_per_doctor(self, doctors):
        total_appointments_per_doctor = {}
        appointments = self.get_section_data("appointments")
        for doctor in doctors:
            total_appointments_per_doctor[doctor] = sum(
                'Doctor: ' + doctor.split(',')[0] in a for a in appointments)
        return total_appointments_per_doctor

    def calculate_total_patients_by_illness_type(self):
        total_patients_by_illness_type = {}
        patient_illness = self.get_section_data("patients")
        for record in patient_illness:
            if "Illness:" in record:
                illness_type = record.split("Illness:")[1].strip().split(",")[0]
                total_patients_by_illness_type[illness_type] = total_patients_by_illness_type.get(illness_type, 0) + 1
        return total_patients_by_illness_type

    def format_management_report(self, doctors, total_patients_per_doctor, total_appointments_per_doctor,
                                 total_patients_by_illness_type):
        report = "Management Report:\n\n"
        report += f"Total Number of Doctors in the System: {len(doctors)}\n\n"
        report += "Total Number of Patients per Doctor:\n"
        for doctor, total_patients in total_patients_per_doctor.items():
            report += f"  - {doctor.split(',')[0]}: {total_patients}\n"

        report += "\nTotal Number of Appointments per Month per Doctor:\n"
        for doctor, total_appointments in total_appointments_per_doctor.items():
            report += f"  - {doctor.split(',')[0]}: {total_appointments}\n"

        report += "\nTotal Number of Patients Based on Illness Type:\n"
        for illness_type, total_patients in total_patients_by_illness_type.items():
            report += f"  - {illness_type}: {total_patients}\n"

        return report

    def get_patients_assigned_to_doctor(self, doctor_name):
        assignments = self.get_section_data("patient_assignments")
        patients_assigned = []
        for assignment in assignments:
            if f"Doctor: {doctor_name.split(',')[0]}" in assignment:
                parts = assignment.split(" - ")
                for part in parts:
                    if part.startswith("Patient:"):
                        patient_name = part.replace("Patient:", "").strip()
                        patients_assigned.append(patient_name)
        return patients_assigned


if __name__ == "__main__":
    root = tk.Tk()
    app = MedicalCentreApp(root)
    root.mainloop()