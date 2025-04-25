from flask import Flask, render_template, redirect, url_for, flash, request, jsonify, session, abort # Add abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta, date # Import timedelta and date here
import os
import json
from functools import wraps
from sqlalchemy import func # Import func
from sqlalchemy.exc import OperationalError, IntegrityError # Import OperationalError and IntegrityError

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-key-for-testing')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///barangay.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Security & User Management - Role-Based Access Control
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='staff')  # admin, doctor, nurse, staff
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Add relationship to certificates issued by this user
    issued_certificates = db.relationship('Certificate', backref='issuer', lazy=True)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# Audit Logs for Security Tracking
class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    action = db.Column(db.String(100), nullable=False)
    details = db.Column(db.Text)
    ip_address = db.Column(db.String(50))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    user = db.relationship('User', backref='audit_logs')

# Existing Models
class Resident(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    address = db.Column(db.String(200), nullable=False)
    contact_number = db.Column(db.String(20))
    birth_date = db.Column(db.Date)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_patient = db.Column(db.Boolean, default=False)

class Certificate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    resident_id = db.Column(db.Integer, db.ForeignKey('resident.id'), nullable=False)
    type = db.Column(db.String(50), nullable=False)
    purpose = db.Column(db.String(200))
    issue_date = db.Column(db.DateTime, default=datetime.utcnow)
    # Add the missing issued_by_id column
    issued_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True) # Allow null if needed, or set nullable=False if required
    
    resident = db.relationship('Resident', backref='certificates')
    # The backref 'issuer' is defined in the User model

class Announcement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# New Model for Blotter Records
class BlotterRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    complainant_name = db.Column(db.String(150), nullable=False)
    respondent_name = db.Column(db.String(150))
    incident_type = db.Column(db.String(100), nullable=False)
    incident_location = db.Column(db.String(200))
    incident_datetime = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    details = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(50), default='Open') # e.g., Open, Under Investigation, Settled, Closed, Referred
    recorded_by_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    recorded_by = db.relationship('User', backref='recorded_blotters')

    def __repr__(self):
        return f'<BlotterRecord {self.id} - {self.incident_type}>'

# Healthcare models - Patient Records Module
class Patient(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    resident_id = db.Column(db.Integer, db.ForeignKey('resident.id'), nullable=False)
    medical_history = db.Column(db.Text)
    blood_type = db.Column(db.String(10))
    allergies = db.Column(db.Text)
    emergency_contact = db.Column(db.String(100))
    emergency_number = db.Column(db.String(20))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    resident = db.relationship('Resident', backref='patient_profile')
    
# Appointment Management System
class Appointment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('patient.id'), nullable=False)
    doctor_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    appointment_date = db.Column(db.DateTime, nullable=False)
    purpose = db.Column(db.String(200), nullable=False)
    status = db.Column(db.String(20), default='scheduled')  # scheduled, completed, cancelled
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    patient = db.relationship('Patient', backref='appointments')
    doctor = db.relationship('User', backref='doctor_appointments')

# Inventory Tracking System Models
class InventoryCategory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.Text)
    # Relationship to Items (One-to-Many) - Defines InventoryCategory.items and InventoryItem.category
    items = db.relationship('InventoryItem', backref='category', lazy=True)

    def __repr__(self):
        return f'<InventoryCategory {self.name}>'

class InventoryItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text)
    quantity = db.Column(db.Integer, default=0)
    unit = db.Column(db.String(50)) # e.g., 'pcs', 'boxes', 'bottles'
    category_id = db.Column(db.Integer, db.ForeignKey('inventory_category.id'))
    low_stock_threshold = db.Column(db.Integer, default=10)
    expiry_date = db.Column(db.Date, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationship to Transactions (One-to-Many)
    # Define backref here - this creates InventoryTransaction.item
    transactions = db.relationship('InventoryTransaction', backref='item', lazy=True, cascade="all, delete-orphan") 

    def __repr__(self):
        return f'<InventoryItem {self.name}>'

class InventoryTransaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    item_id = db.Column(db.Integer, db.ForeignKey('inventory_item.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False) # Amount added or removed
    transaction_type = db.Column(db.String(10), nullable=False) # 'in', 'out', 'initial', 'correction'
    transaction_date = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    notes = db.Column(db.Text)

    # Remove the explicit relationship definition for 'item'
    # item = db.relationship('InventoryItem') # Removed - backref='item' in InventoryItem handles this
    user = db.relationship('User', backref='inventory_transactions')

    def __repr__(self):
        # Access item via the backref created by InventoryItem
        item_name = self.item.name if self.item else 'Unknown Item'
        return f'<InventoryTransaction {self.id} - {item_name} {self.transaction_type} {self.quantity}>'

# Medical Record
class MedicalRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('patient.id'), nullable=False)
    doctor_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    diagnosis = db.Column(db.Text, nullable=False)
    treatment = db.Column(db.Text)
    prescription = db.Column(db.Text)
    visit_date = db.Column(db.DateTime, default=datetime.utcnow)
    follow_up_date = db.Column(db.Date)
    notes = db.Column(db.Text)

    patient = db.relationship('Patient', backref='medical_records')
    doctor = db.relationship('User', backref='doctor_records')

# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Role-based access decorator:
def role_required(roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated or current_user.role not in roles:
                flash('You do not have permission to access this page.', 'danger')
                return redirect(url_for('login'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Log audit function
def log_audit(action, details=None):
    if current_user.is_authenticated:
        log = AuditLog(
            user_id=current_user.id,
            action=action,
            details=details,
            ip_address=request.remote_addr
        )
        db.session.add(log)
        db.session.commit()

# Routes
# Authentication routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            log_audit('User login')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))
        flash('Invalid username or password', 'danger')
    return render_template('login.html', title='Login')

@app.route('/logout')
@login_required
def logout():
    log_audit('User logout')
    logout_user()
    return redirect(url_for('login'))

# Existing routes
@app.route('/')
@login_required
def index():
    announcements = Announcement.query.order_by(Announcement.created_at.desc()).limit(3).all()
    total_residents = Resident.query.count()
    total_patients = Patient.query.count()
    total_appointments = Appointment.query.count()
    
    inventory_alerts = 0 # Default value
    try:
        # Try to get the count using func.count
        inventory_alerts = db.session.query(func.count(InventoryItem.id)).filter(
            InventoryItem.quantity <= InventoryItem.low_stock_threshold
        ).scalar() # Use scalar() to get the count value
    except OperationalError as e:
        # Check if the error is about the missing column
        if 'no such column' in str(e).lower() and 'low_stock_threshold' in str(e).lower():
             flash('Warning: Could not retrieve inventory alerts. Database schema might be outdated (missing low_stock_threshold column). Please run database migrations.', 'warning')
             # Log the error for the admin/developer
             app.logger.error(f"Database schema error accessing inventory alerts: {e}")
        else:
             # Re-raise other operational errors
             raise e
    except Exception as e:
        # Catch other potential exceptions during the query
        flash('An unexpected error occurred while retrieving inventory alerts.', 'danger')
        app.logger.error(f"Unexpected error accessing inventory alerts: {e}")
        # Keep inventory_alerts as 0
    
    upcoming_appointments = Appointment.query.filter(
        Appointment.appointment_date >= datetime.utcnow(),
        Appointment.status == 'scheduled'
    ).order_by(Appointment.appointment_date).limit(5).all()
    
    return render_template('index.html', 
                           title='Dashboard', 
                           announcements=announcements,
                           total_residents=total_residents,
                           total_patients=total_patients,
                           total_appointments=total_appointments,
                           inventory_alerts=inventory_alerts, # Pass the count (or 0 if error)
                           upcoming_appointments=upcoming_appointments)

@app.route('/residents')
@login_required
def residents():
    residents_list = Resident.query.all()
    return render_template('residents.html', title='Residents', residents=residents_list)

# Add route to handle adding a new resident
@app.route('/residents/add', methods=['POST'])
@login_required
@role_required(['admin', 'staff']) # Adjust roles as needed
def add_resident():
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400

    data = request.get_json()
    first_name = data.get('firstName')
    last_name = data.get('lastName')
    address = data.get('address')
    contact_number = data.get('contactNumber')
    birth_date_str = data.get('birthDate')

    if not first_name or not last_name or not address:
        return jsonify({"error": "Missing required fields (First Name, Last Name, Address)"}), 400

    birth_date = None
    if birth_date_str:
        try:
            birth_date = datetime.strptime(birth_date_str, '%Y-%m-%d').date()
        except ValueError:
            return jsonify({"error": "Invalid birth date format. Use YYYY-MM-DD."}), 400

    try:
        new_resident = Resident(
            first_name=first_name,
            last_name=last_name,
            address=address,
            contact_number=contact_number,
            birth_date=birth_date
        )
        db.session.add(new_resident)
        db.session.commit()
        log_audit('Added new resident', f'Name: {first_name} {last_name}')
        # Return the created resident data (optional, but good practice)
        return jsonify({
            "message": "Resident added successfully!",
            "resident": {
                "id": new_resident.id,
                "first_name": new_resident.first_name,
                "last_name": new_resident.last_name,
                "address": new_resident.address,
                "contact_number": new_resident.contact_number,
                "birth_date": new_resident.birth_date.strftime('%Y-%m-%d') if new_resident.birth_date else None
            }
        }), 201 # HTTP 201 Created status
    except IntegrityError:
        db.session.rollback()
        return jsonify({"error": "Database integrity error. Perhaps a unique constraint failed?"}), 500
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error adding resident: {e}")
        return jsonify({"error": "An unexpected error occurred."}), 500

# Add route to handle editing an existing resident
@app.route('/residents/edit/<int:id>', methods=['PUT']) # Use PUT for updates
@login_required
@role_required(['admin', 'staff'])
def edit_resident(id):
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400

    resident_to_edit = Resident.query.get_or_404(id)
    data = request.get_json()

    first_name = data.get('firstName')
    last_name = data.get('lastName')
    address = data.get('address')
    contact_number = data.get('contactNumber')
    birth_date_str = data.get('birthDate')

    if not first_name or not last_name or not address:
        return jsonify({"error": "Missing required fields (First Name, Last Name, Address)"}), 400

    birth_date = None
    if birth_date_str:
        try:
            birth_date = datetime.strptime(birth_date_str, '%Y-%m-%d').date()
        except ValueError:
            return jsonify({"error": "Invalid birth date format. Use YYYY-MM-DD."}), 400

    try:
        resident_to_edit.first_name = first_name
        resident_to_edit.last_name = last_name
        resident_to_edit.address = address
        resident_to_edit.contact_number = contact_number
        resident_to_edit.birth_date = birth_date

        db.session.commit()
        log_audit('Updated resident', f'Resident ID: {id}, Name: {first_name} {last_name}')
        return jsonify({"message": "Resident updated successfully!"}), 200
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error updating resident {id}: {e}")
        return jsonify({"error": "An unexpected error occurred during update."}), 500

# Add route to handle deleting a resident
@app.route('/residents/delete/<int:id>', methods=['DELETE']) # Use DELETE method
@login_required
@role_required(['admin', 'staff']) # Or maybe just admin
def delete_resident(id):
    resident_to_delete = Resident.query.get_or_404(id)

    # Optional: Add checks here if resident is linked to other critical data (patients, certificates)
    # if resident_to_delete.certificates or resident_to_delete.patient_profile:
    #     return jsonify({"error": "Cannot delete resident with associated certificates or patient profile."}), 400

    try:
        resident_name = f"{resident_to_delete.first_name} {resident_to_delete.last_name}"
        db.session.delete(resident_to_delete)
        db.session.commit()
        log_audit('Deleted resident', f'Resident ID: {id}, Name: {resident_name}')
        return jsonify({"message": "Resident deleted successfully!"}), 200
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error deleting resident {id}: {e}")
        return jsonify({"error": "An unexpected error occurred during deletion."}), 500


@app.route('/certificates')
@login_required
@role_required(['admin', 'staff']) # Or adjust roles as needed
def certificates():
    # Fetch existing certificates (assuming you have a Certificate model)
    # Replace with your actual Certificate model and query
    try:
        # Query existing certificates (adjust model name if needed)
        issued_certificates = Certificate.query.order_by(Certificate.issue_date.desc()).all()
        # Query ALL residents to populate the dropdown in the modal
        all_residents = Resident.query.order_by(Resident.last_name, Resident.first_name).all()
    except OperationalError as e:
        flash(f"Database error: {e}. Could not load certificate or resident data.", 'danger')
        issued_certificates = []
        all_residents = []
    except Exception as e:
        flash(f"An unexpected error occurred: {e}", 'danger')
        issued_certificates = []
        all_residents = []

    return render_template('certificates.html', 
                           title="Manage Certificates", 
                           certificates=issued_certificates,
                           residents=all_residents) # Pass residents to the template

# Add routes for issuing, printing, deleting certificates (using POST requests and potentially fetching data for print view)
# Example placeholders:

@app.route('/certificates/issue', methods=['POST'])
@login_required
@role_required(['admin', 'staff'])
def issue_certificate():
    # Logic to handle form submission from the modal
    # Get resident_id, type, purpose from request.form
    # Create new Certificate object
    # Add to db.session and commit
    # Add audit log entry
    # flash success message
    # redirect back to certificates page
    resident_id = request.form.get('residentId')
    cert_type = request.form.get('type')
    purpose = request.form.get('purpose')
    user_id = current_user.id

    if not resident_id or not cert_type or not purpose:
        flash('Missing required fields for certificate.', 'danger')
        return redirect(url_for('certificates'))

    try:
        resident = Resident.query.get(resident_id)
        if not resident:
            flash('Selected resident not found.', 'danger')
            return redirect(url_for('certificates'))

        new_cert = Certificate(
            resident_id=resident_id,
            type=cert_type,
            purpose=purpose,
            issued_by_id=user_id
        )
        db.session.add(new_cert)
        
        # Add Audit Log
        log_audit(f"Issued {cert_type} for {resident.first_name} {resident.last_name}")

        db.session.commit()
        flash(f'{cert_type} issued successfully for {resident.first_name} {resident.last_name}.', 'success')

    except IntegrityError:
        db.session.rollback()
        flash('Database error: Could not issue certificate due to an integrity constraint.', 'danger')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error issuing certificate: {e}", exc_info=True) 
        flash(f'An unexpected error occurred while issuing the certificate.', 'danger')
        
    return redirect(url_for('certificates'))


@app.route('/certificates/delete/<int:id>', methods=['POST']) # Use POST for delete
@login_required
@role_required(['admin', 'staff']) # Or admin only
def delete_certificate(id):
    try:
        cert_to_delete = Certificate.query.get_or_404(id)
        resident_name = f"{cert_to_delete.resident.first_name} {cert_to_delete.resident.last_name}"
        cert_type = cert_to_delete.type
        
        db.session.delete(cert_to_delete)
        
        # Add Audit Log
        log_action(f"Deleted {cert_type} for {resident_name} (ID: {id})", current_user.id)
        
        db.session.commit()
        flash(f'Certificate (ID: {id}) deleted successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting certificate: {e}', 'danger')
        
    return redirect(url_for('certificates'))

# Route for printing - might generate a PDF or render a specific print template
@app.route('/certificates/print/<int:id>')
@login_required
@role_required(['admin', 'staff'])
def print_certificate(id):
    cert = Certificate.query.get_or_404(id)
    # Render a print-specific template
    return render_template('print_certificate.html', certificate=cert, title=f"Print Certificate - {cert.type}")
    # Or use a PDF library like WeasyPrint or FPDF
    # flash('Print functionality not fully implemented yet.', 'info')
    # return redirect(url_for('certificates'))

@app.route('/announcements')
@login_required
def announcements():
    announcements_list = Announcement.query.order_by(Announcement.created_at.desc()).all()
    return render_template('announcements.html', title='Announcements', announcements=announcements_list)

# Add route to handle adding a new announcement
@app.route('/announcements/add', methods=['POST'])
@login_required
@role_required(['admin', 'staff']) # Adjust roles as needed
def add_announcement():
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400

    data = request.get_json()
    title = data.get('title')
    content = data.get('content')

    if not title or not content:
        return jsonify({"error": "Missing required fields (Title, Content)"}), 400

    try:
        new_announcement = Announcement(
            title=title,
            content=content
            # created_at is handled by default
        )
        db.session.add(new_announcement)
        db.session.commit()
        log_audit('Added new announcement', f'Title: {title}')
        return jsonify({
            "message": "Announcement published successfully!",
            "announcement": {
                "id": new_announcement.id,
                "title": new_announcement.title,
                "content": new_announcement.content,
                "created_at": new_announcement.created_at.isoformat()
            }
        }), 201
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error adding announcement: {e}")
        return jsonify({"error": "An unexpected error occurred."}), 500

# Add route to handle editing an existing announcement
@app.route('/announcements/edit/<int:id>', methods=['PUT'])
@login_required
@role_required(['admin', 'staff'])
def edit_announcement(id):
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400

    announcement_to_edit = Announcement.query.get_or_404(id)
    data = request.get_json()
    title = data.get('title')
    content = data.get('content')

    if not title or not content:
        return jsonify({"error": "Missing required fields (Title, Content)"}), 400

    try:
        announcement_to_edit.title = title
        announcement_to_edit.content = content
        # updated_at could be added to the model if needed

        db.session.commit()
        log_audit('Updated announcement', f'Announcement ID: {id}, Title: {title}')
        return jsonify({"message": "Announcement updated successfully!"}), 200
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error updating announcement {id}: {e}")
        return jsonify({"error": "An unexpected error occurred during update."}), 500

# Add route to handle deleting an announcement
@app.route('/announcements/delete/<int:id>', methods=['DELETE'])
@login_required
@role_required(['admin', 'staff']) # Or maybe just admin
def delete_announcement(id):
    announcement_to_delete = Announcement.query.get_or_404(id)

    try:
        title = announcement_to_delete.title
        db.session.delete(announcement_to_delete)
        db.session.commit()
        log_audit('Deleted announcement', f'Announcement ID: {id}, Title: {title}')
        return jsonify({"message": "Announcement deleted successfully!"}), 200
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error deleting announcement {id}: {e}")
        return jsonify({"error": "An unexpected error occurred during deletion."}), 500


# ---------------- Blotter Management System ----------------
@app.route('/blotter')
@login_required
@role_required(['admin', 'staff'])
def blotter():
    records = BlotterRecord.query.order_by(BlotterRecord.incident_datetime.desc()).all()
    return render_template('blotter.html', title='Blotter Records', records=records)

@app.route('/blotter/add', methods=['GET', 'POST'])
@login_required
@role_required(['admin', 'staff'])
def add_blotter():
    if request.method == 'POST':
        complainant_name = request.form.get('complainant_name')
        respondent_name = request.form.get('respondent_name')
        incident_type = request.form.get('incident_type')
        incident_location = request.form.get('incident_location')
        incident_datetime_str = request.form.get('incident_datetime')
        details = request.form.get('details')
        status = request.form.get('status', 'Open') # Default to Open if not provided

        try:
            incident_datetime = datetime.strptime(incident_datetime_str, '%Y-%m-%dT%H:%M')
        except (ValueError, TypeError):
            flash('Invalid date/time format.', 'danger')
            return render_template('add_blotter.html', title='Add Blotter Record') # Re-render form

        new_record = BlotterRecord(
            complainant_name=complainant_name,
            respondent_name=respondent_name,
            incident_type=incident_type,
            incident_location=incident_location,
            incident_datetime=incident_datetime,
            details=details,
            status=status,
            recorded_by_id=current_user.id
        )
        db.session.add(new_record)
        db.session.commit()
        log_audit('Added blotter record', f'Incident Type: {incident_type}, Complainant: {complainant_name}')
        flash('Blotter record added successfully.', 'success')
        return redirect(url_for('blotter'))

    return render_template('add_blotter.html', title='Add Blotter Record')

@app.route('/blotter/view/<int:id>')
@login_required
@role_required(['admin', 'staff'])
def view_blotter(id):
    record = BlotterRecord.query.get_or_404(id)
    return render_template('view_blotter.html', title='View Blotter Record', record=record)

# Add route for printing a blotter record
@app.route('/blotter/print/<int:id>')
@login_required
@role_required(['admin', 'staff'])
def print_blotter(id):
    record = BlotterRecord.query.get_or_404(id)
    return render_template('print_blotter.html', record=record, title=f"Print Blotter Record - B-{record.id}")

@app.route('/blotter/edit/<int:id>', methods=['GET', 'POST'])
@login_required
@role_required(['admin', 'staff'])
def edit_blotter(id):
    record = BlotterRecord.query.get_or_404(id)
    if request.method == 'POST':
        record.complainant_name = request.form.get('complainant_name')
        record.respondent_name = request.form.get('respondent_name')
        record.incident_type = request.form.get('incident_type')
        record.incident_location = request.form.get('incident_location')
        incident_datetime_str = request.form.get('incident_datetime')
        record.details = request.form.get('details')
        record.status = request.form.get('status')

        try:
            record.incident_datetime = datetime.strptime(incident_datetime_str, '%Y-%m-%dT%H:%M')
        except (ValueError, TypeError):
            flash('Invalid date/time format.', 'danger')
            return render_template('edit_blotter.html', title='Edit Blotter Record', record=record) # Re-render form

        db.session.commit()
        log_audit('Updated blotter record', f'Record ID: {id}, Status: {record.status}')
        flash('Blotter record updated successfully.', 'success')
        return redirect(url_for('blotter'))

    # Format datetime for the input field
    record.incident_datetime_str = record.incident_datetime.strftime('%Y-%m-%dT%H:%M')
    return render_template('edit_blotter.html', title='Edit Blotter Record', record=record)

@app.route('/blotter/delete/<int:id>', methods=['POST'])
@login_required
@role_required(['admin']) # Only admin can delete
def delete_blotter(id):
    record = BlotterRecord.query.get_or_404(id)
    incident_type = record.incident_type # Get details before deleting
    complainant = record.complainant_name
    db.session.delete(record)
    db.session.commit()
    log_audit('Deleted blotter record', f'Record ID: {id}, Incident: {incident_type}, Complainant: {complainant}')
    flash('Blotter record deleted successfully.', 'success')
    return redirect(url_for('blotter'))

# ---------------- Healthcare Management System ----------------
# Healthcare routes
# Patient Records Module
@app.route('/patients')
@login_required
@role_required(['admin', 'doctor', 'nurse'])
def patients():
    patients_list = Patient.query.join(Resident).all()
    return render_template('patients.html', title='Patients', patients=patients_list)

@app.route('/patients/add', methods=['GET', 'POST'])
@login_required
@role_required(['admin', 'doctor', 'nurse'])
def add_patient():
    if request.method == 'POST':
        resident_id = request.form.get('resident_id')

        # Check if resident exists and is not already a patient
        resident = Resident.query.get(resident_id)
        if not resident:
            flash('Resident not found', 'danger')
            return redirect(url_for('patients'))

        existing_patient = Patient.query.filter_by(resident_id=resident_id).first()
        if existing_patient:
            flash('This resident is already registered as a patient', 'warning')
            return redirect(url_for('patients'))

        new_patient = Patient(
            resident_id=resident_id,
            medical_history=request.form.get('medical_history'),
            blood_type=request.form.get('blood_type'),
            allergies=request.form.get('allergies'),
            emergency_contact=request.form.get('emergency_contact'),
            emergency_number=request.form.get('emergency_number')
        )
        
        resident.is_patient = True
        
        db.session.add(new_patient)
        db.session.commit()
        
        log_audit('Added new patient', f'Patient ID: {new_patient.id}, Resident: {resident.first_name} {resident.last_name}')
        flash('Patient added successfully', 'success')
        return redirect(url_for('patients'))
    
    residents = Resident.query.filter_by(is_patient=False).all()
    return render_template('add_patient.html', title='Add Patient', residents=residents)

@app.route('/patients/<int:id>')
@login_required
@role_required(['admin', 'doctor', 'nurse'])
def patient_details(id):
    patient = Patient.query.get_or_404(id)
    medical_records = MedicalRecord.query.filter_by(patient_id=id).order_by(MedicalRecord.visit_date.desc()).all()
    appointments = Appointment.query.filter_by(patient_id=id).order_by(Appointment.appointment_date.desc()).all()
    return render_template('patient_details.html', 
                          title=f'Patient: {patient.resident.first_name} {patient.resident.last_name}',
                          patient=patient,
                          medical_records=medical_records,
                          appointments=appointments)

# Appointment Management System
@app.route('/appointments')
@login_required
def appointments():
    today = datetime.utcnow().date()
    upcoming = Appointment.query.filter(
        Appointment.appointment_date.cast(db.Date) >= today,
        Appointment.status == 'scheduled'
    ).order_by(Appointment.appointment_date).all()
    past = Appointment.query.filter(
        Appointment.appointment_date.cast(db.Date) < today,
        Appointment.status.in_(['scheduled', 'completed'])
    ).order_by(Appointment.appointment_date.desc()).all()
    
    return render_template('appointments.html', 
                          title='Appointments', 
                          upcoming=upcoming, 
                          past=past)

@app.route('/appointments/add', methods=['GET', 'POST'])
@login_required
@role_required(['admin', 'doctor', 'nurse'])
def add_appointment():
    if request.method == 'POST':
        patient_id = request.form.get('patient_id')
        doctor_id = request.form.get('doctor_id')
        appointment_date = datetime.strptime(request.form.get('appointment_date'), '%Y-%m-%dT%H:%M')
        purpose = request.form.get('purpose')
        
        appointment = Appointment(
            patient_id=patient_id,
            doctor_id=doctor_id,
            appointment_date=appointment_date,
            purpose=purpose,
            status='scheduled'
        )
        
        db.session.add(appointment)
        db.session.commit()
        
        log_audit('Added new appointment', f'Appointment ID: {appointment.id}, Date: {appointment_date}')
        flash('Appointment scheduled successfully', 'success')
        return redirect(url_for('appointments'))
                
    patients = Patient.query.join(Resident).all()
    doctors = User.query.filter_by(role='doctor').all()
    return render_template('add_appointment.html', 
                          title='Schedule Appointment', 
                          patients=patients,
                          doctors=doctors)

# Inventory Tracking System
@app.route('/inventory')
@login_required
@role_required(['admin', 'doctor', 'nurse', 'staff']) # Added 'doctor'
def inventory():
    categories = InventoryCategory.query.all()
    inventory_items = [] # Default to empty list
    low_stock = [] # Default to empty list
    schema_warning_flashed = False # Flag to avoid duplicate warnings

    try:
        inventory_items = InventoryItem.query.all()
    except OperationalError as e:
        if 'no such column' in str(e).lower():
            flash('Warning: Could not retrieve full inventory list. Database schema might be outdated. Please run database migrations.', 'warning')
            app.logger.error(f"Database schema error in /inventory (query.all): {e}")
            schema_warning_flashed = True
        else:
            raise e # Re-raise unexpected operational errors
    except Exception as e:
        flash('An unexpected error occurred while retrieving inventory items.', 'danger')
        app.logger.error(f"Unexpected error in /inventory (query.all): {e}")

    try:
        # Check for potential column name mismatch (reorder_level vs low_stock_threshold)
        # Assuming the model uses low_stock_threshold based on previous errors
        low_stock = InventoryItem.query.filter(InventoryItem.quantity <= InventoryItem.low_stock_threshold).all()
    except OperationalError as e:
        if 'no such column' in str(e).lower():
             # Only flash if the previous query didn't already flash a similar warning
            if not schema_warning_flashed:
                 flash('Warning: Could not retrieve low stock items. Database schema might be outdated. Please run database migrations.', 'warning')
            app.logger.error(f"Database schema error in /inventory (low_stock query): {e}")
        else:
             raise e # Re-raise unexpected operational errors
    except Exception as e:
        flash('An unexpected error occurred while retrieving low stock items.', 'danger')
        app.logger.error(f"Unexpected error in /inventory (low_stock query): {e}")

    today = date.today() # Get today's date
    return render_template('inventory.html',
                          title='Inventory',
                          categories=categories,
                          inventory=inventory_items, # Will be empty list if error occurred
                          low_stock=low_stock,       # Will be empty list if error occurred
                          today_date=today)

@app.route('/inventory/add_item', methods=['GET', 'POST'])
@login_required
@role_required(['admin', 'nurse', 'staff']) # Kept as is - doctors likely shouldn't add new item types
def add_inventory_item():
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description') # Assuming you might add this field to your form
        category_id = request.form.get('category_id')
        quantity = request.form.get('quantity', type=int)
        unit = request.form.get('unit')
        # Use low_stock_threshold from form (ensure form field name matches)
        low_stock_threshold = request.form.get('low_stock_threshold', type=int, default=10) 
        expiry_date = request.form.get('expiry_date')
        
        if expiry_date:
            expiry_date = datetime.strptime(expiry_date, '%Y-%m-%d').date()
                
        item = InventoryItem(
            name=name,
            description=description, # Add description if applicable
            category_id=category_id, # Removed stray 'level,'
            quantity=quantity,
            unit=unit,
            low_stock_threshold=low_stock_threshold, # Use the correct attribute name
            expiry_date=expiry_date
        )
        db.session.add(item)
        
        # Add transaction record
        transaction = InventoryTransaction(
            item=item,
            quantity=quantity,
            transaction_type='in', # Changed from 'initial' to 'in' for consistency, or keep 'initial' if preferred
            user_id=current_user.id,
            notes='Initial stock' # Keep notes as 'Initial stock' or similar
        )
        db.session.add(transaction)
        db.session.commit()
        
        log_audit('Added inventory item', f'Item: {name}, Quantity: {quantity}')
        flash('Inventory item added successfully', 'success')
        return redirect(url_for('inventory'))
    
    categories = InventoryCategory.query.all()
    # Pass a default item object or None if needed by the template for default values
    return render_template('add_inventory.html', title='Add Inventory Item', categories=categories)

# Route for adjusting inventory stock
@app.route('/inventory/adjust/<int:id>', methods=['GET', 'POST'])
@login_required
@role_required(['admin', 'doctor', 'nurse', 'staff']) # Added 'doctor'
def adjust_inventory_item(id):
    item = InventoryItem.query.get_or_404(id)
    if request.method == 'POST':
        try:
            adjustment_type = request.form.get('adjustment_type') # 'in' or 'out'
            quantity_change = int(request.form.get('quantity_change'))
            notes = request.form.get('notes', '')

            if quantity_change <= 0:
                flash('Quantity must be a positive number.', 'danger')
                return render_template('adjust_inventory_item.html', title='Adjust Stock', item=item)

            if adjustment_type == 'in':
                item.quantity += quantity_change
                transaction_type = 'in'
                log_details = f'Added {quantity_change} {item.unit} to {item.name}. Notes: {notes}'
            elif adjustment_type == 'out':
                if quantity_change > item.quantity:
                    flash(f'Cannot remove {quantity_change} {item.unit}. Only {item.quantity} available.', 'danger')
                    return render_template('adjust_inventory_item.html', title='Adjust Stock', item=item)
                item.quantity -= quantity_change
                transaction_type = 'out'
                log_details = f'Removed {quantity_change} {item.unit} from {item.name}. Notes: {notes}'
            else:
                flash('Invalid adjustment type selected.', 'danger')
                return render_template('adjust_inventory_item.html', title='Adjust Stock', item=item)

            # Create transaction record
            transaction = InventoryTransaction(
                item_id=item.id,
                quantity=quantity_change,
                transaction_type=transaction_type,
                user_id=current_user.id,
                notes=notes
            )
            db.session.add(transaction)
            db.session.commit()
            
            log_audit('Adjusted inventory stock', log_details)
            flash(f'Stock for {item.name} adjusted successfully.', 'success')
            return redirect(url_for('inventory'))
                
        except ValueError:
            flash('Invalid quantity entered. Please enter a number.', 'danger')
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred: {str(e)}', 'danger')
            
    # GET request
    return render_template('adjust_inventory_item.html', title='Adjust Stock', item=item)

# Route for viewing inventory item history
@app.route('/inventory/history/<int:id>')
@login_required
@role_required(['admin', 'doctor', 'nurse', 'staff']) # Added 'doctor'
def inventory_history(id):
    item = InventoryItem.query.get_or_404(id)
    transactions = InventoryTransaction.query.filter_by(item_id=id).order_by(InventoryTransaction.transaction_date.desc()).all()
    return render_template('inventory_history.html', title=f'History for {item.name}', item=item, transactions=transactions)

# Route for deleting an inventory item
@app.route('/inventory/delete/<int:id>', methods=['POST'])
@login_required
@role_required(['admin']) # Only admin can delete items
def delete_inventory_item(id):
    item_to_delete = InventoryItem.query.get_or_404(id)
    
    # Optional: Check if there are transactions associated. Decide if deletion is allowed.
    if item_to_delete.transactions:
         flash(f'Cannot delete "{item_to_delete.name}" as it has transaction history. Consider setting quantity to 0 instead.', 'warning')
         return redirect(url_for('inventory'))
         # Alternatively, delete transactions first or handle deletion differently.
         # For now, we prevent deletion if history exists.

    item_name = item_to_delete.name # Get name before deleting    
    db.session.delete(item_to_delete)
    db.session.commit()
    
    log_audit('Deleted inventory item', f'Item ID: {id}, Name: {item_name}')
    flash(f'Inventory item "{item_name}" deleted successfully.', 'success')
    return redirect(url_for('inventory'))

# Medical Records
@app.route('/medical_records/add/<int:patient_id>', methods=['GET', 'POST'])
@login_required
@role_required(['admin', 'doctor'])
def add_medical_record(patient_id):
    patient = Patient.query.get_or_404(patient_id)
    
    if request.method == 'POST':
        record = MedicalRecord(
            patient_id=patient_id,
            doctor_id=current_user.id,
            diagnosis=request.form.get('diagnosis'),
            treatment=request.form.get('treatment'),
            prescription=request.form.get('prescription'),
            notes=request.form.get('notes')
        )
        follow_up = request.form.get('follow_up_date')
        if follow_up:
            record.follow_up_date = datetime.strptime(follow_up, '%Y-%m-%d').date()
        
        db.session.add(record)
        db.session.commit()
        
        # Update appointment status if this was for an appointment
        appointment_id = request.form.get('appointment_id')
        if appointment_id:
            appointment = Appointment.query.get(appointment_id)
            if appointment:
                appointment.status = 'completed'
                db.session.commit()
                    
        log_audit('Added medical record', f'Patient ID: {patient_id}, Record ID: {record.id}')
        flash('Medical record added successfully', 'success')
        return redirect(url_for('patient_details', id=patient_id))
    
    # Check if this is for a specific appointment
    appointment_id = request.args.get('appointment_id')
    appointment = None
    if appointment_id:
        appointment = Appointment.query.get(appointment_id)
        
    return render_template('add_medical_record.html', 
                          title='Add Medical Record', 
                          patient=patient,
                          appointment=appointment)

# Security & Audit Logs
@app.route('/audit_logs')
@login_required
@role_required(['admin'])
def audit_logs():
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).all()
    return render_template('audit_logs.html', title='Audit Logs', logs=logs)

# User Management
@app.route('/users')
@login_required
@role_required(['admin'])
def users():
    all_users = User.query.order_by(User.username).all() # Fetch all users from the database
    # Add print statement for debugging: Check Flask console output
    print(f"--- Debug: Fetched users for /users page: {[user.username for user in all_users]} ---") 
    return render_template('users.html', users=all_users, title='User Management')

@app.route('/users/add', methods=['GET', 'POST'])
@login_required
@role_required(['admin'])
def add_user():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role')
        
        # Check if user already exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
            return redirect(url_for('add_user'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already in use', 'danger')
            return redirect(url_for('add_user'))
        
        user = User(username=username, email=email, role=role)
        user.set_password(password)
        
        db.session.add(user)
        db.session.commit()
        
        log_audit('Added new user', f'Username: {username}, Role: {role}')
        flash('User added successfully', 'success')
        return redirect(url_for('users'))
    
    return render_template('add_user.html', title='Add User')

# Route for editing a user
@app.route('/users/edit/<int:id>', methods=['GET', 'POST'])
@login_required
@role_required(['admin'])
def edit_user(id):
    user_to_edit = User.query.get_or_404(id)
    if request.method == 'POST':
        # Get data from form
        username = request.form.get('username')
        email = request.form.get('email')
        role = request.form.get('role')
        
        # Check for uniqueness if username/email changed
        if username != user_to_edit.username and User.query.filter_by(username=username).first():
            flash('Username already exists.', 'danger')
            return render_template('edit_user.html', title='Edit User', user=user_to_edit) # Re-render with error
            
        if email != user_to_edit.email and User.query.filter_by(email=email).first():
            flash('Email already in use.', 'danger')
            return render_template('edit_user.html', title='Edit User', user=user_to_edit) # Re-render with error

        # Update user details
        user_to_edit.username = username
        user_to_edit.email = email
        user_to_edit.role = role
        # Optional: Handle password change (requires more fields/logic)
        # password = request.form.get('password')
        # if password:
        #     user_to_edit.set_password(password)
            
        db.session.commit()
        log_audit('Updated user', f'User ID: {id}, Username: {username}, Role: {role}')
        flash('User updated successfully!', 'success')
        return redirect(url_for('users'))
    
    # GET request: Show the edit form pre-filled with user data
    return render_template('edit_user.html', title='Edit User', user=user_to_edit)

# Route for deleting a user
@app.route('/users/delete/<int:id>', methods=['POST'])
@login_required
@role_required(['admin'])
def delete_user(id):
    user_to_delete = User.query.get_or_404(id)
    # Prevent admin from deleting themselves
    if user_to_delete.id == current_user.id:
        flash('You cannot delete your own account.', 'danger')
        return redirect(url_for('users'))
    # Add logic here if users are linked to other critical data (e.g., audit logs, records)
    # You might want to anonymize or reassign ownership instead of hard deleting.
    username = user_to_delete.username # Get username before deleting
    db.session.delete(user_to_delete)
    db.session.commit()
    
    log_audit('Deleted user', f'User ID: {id}, Username: {username}')
    flash(f'User {username} deleted successfully.', 'success')
    return redirect(url_for('users'))

# API endpoints
@app.route('/api/residents')
@login_required
def api_residents():
    residents_list = Resident.query.all()
    result = []
    for resident in residents_list:
        result.append({
            'id': resident.id,
            'name': f"{resident.first_name} {resident.last_name}",
            'address': resident.address,
            'contact': resident.contact_number
        })
    return jsonify(result)

@app.route('/api/inventory/low_stock')
@login_required
def api_low_stock():
    items = []
    try:
        # Filter using the correct column name
        items = InventoryItem.query.filter(InventoryItem.quantity <= InventoryItem.low_stock_threshold).all()
    except OperationalError as e:
        if 'no such column' in str(e).lower():
             flash('Warning: Could not retrieve low stock items via API. Database schema might be outdated.', 'warning')
             app.logger.error(f"Database schema error in /api/inventory/low_stock: {e}")
        else:
             raise e
    except Exception as e:
        app.logger.error(f"Unexpected error in /api/inventory/low_stock: {e}")
        # Optionally return an error response
        # return jsonify({"error": "Could not retrieve low stock items"}), 500

    result = []
    for item in items:
        result.append({
            'id': item.id,
            'name': item.name,
            'quantity': item.quantity,
            'low_stock_threshold': item.low_stock_threshold, # Use the correct attribute name
            'unit': item.unit
        })
    return jsonify(result)

# Run the app
with app.app_context():
    db.create_all()
    
    # Add sample data if database is empty
    if User.query.count() == 0:
        admin = User(username='admin', email='admin@example.com', role='admin')
        admin.set_password('admin123')
        doctor = User(username='doctor', email='doctor@example.com', role='doctor')
        doctor.set_password('doctor123')
        nurse = User(username='nurse', email='nurse@example.com', role='nurse')
        nurse.set_password('nurse123')
        staff = User(username='staff', email='staff@example.com', role='staff')
        staff.set_password('staff123')
        db.session.add_all([admin, doctor, nurse, staff])
        db.session.commit()
        print("Created default users: admin, doctor, nurse, staff (all with password: {username}123)")
    
    if InventoryCategory.query.count() == 0:
        categories = [
            InventoryCategory(name='Medicines', description='All medications and drugs'),
            InventoryCategory(name='Supplies', description='Medical supplies and consumables'),
            InventoryCategory(name='Equipment', description='Medical equipment and devices')
        ]
        db.session.add_all(categories)
        db.session.commit()
        print("Created default inventory categories.")
    
    # Add more comprehensive sample data if residents are missing
    if Resident.query.count() == 0:
        print("Adding sample data...")
        # Sample Residents
        residents_data = [
            {"first_name": "Maria", "last_name": "Santos", "address": "12 Rizal St, Brgy. Pag-asa", "contact_number": "09171234567", "birth_date": "1985-03-15"},
            {"first_name": "Jose", "last_name": "Reyes", "address": "45 Bonifacio Ave, Brgy. Pag-asa", "contact_number": "09229876543", "birth_date": "1992-07-21"},
            {"first_name": "Luz", "last_name": "Garcia", "address": "78 Mabini Blvd, Brgy. Liwanag", "contact_number": "09181122334", "birth_date": "1978-11-02"},
            {"first_name": "Andres", "last_name": "Cruz", "address": "90 Aguinaldo Hi-way, Brgy. Liwanag", "contact_number": "09334455667", "birth_date": "2000-01-30"},
            {"first_name": "Teresa", "last_name": "Lim", "address": "101 Del Pilar St, Brgy. Pag-asa", "contact_number": "09157788990", "birth_date": "1995-05-10"},
        ]
        
        created_residents = []
        for data in residents_data:
            resident = Resident(
                first_name=data["first_name"],
                last_name=data["last_name"],
                address=data["address"],
                contact_number=data["contact_number"],
                birth_date=datetime.strptime(data["birth_date"], "%Y-%m-%d").date()
            )
            db.session.add(resident)
            created_residents.append(resident)
        db.session.commit() # Commit residents to get IDs
        
        # Sample Patients (link to some residents)
        patient1 = Patient(
            resident_id=created_residents[0].id, # Maria Santos
            medical_history="Hypertension, diagnosed 2020.",
            blood_type="O+",
            allergies="Penicillin",
            emergency_contact="Jose Reyes",
            emergency_number="09229876543"
        )
        created_residents[0].is_patient = True
        
        patient2 = Patient(
            resident_id=created_residents[2].id, # Luz Garcia
            medical_history="Asthma since childhood.",
            blood_type="A+",
            allergies="Dust mites",
            emergency_contact="Andres Cruz",
            emergency_number="09334455667"
        )
        created_residents[2].is_patient = True
        
        db.session.add_all([patient1, patient2])
        db.session.commit() # Commit patients to get IDs
        
        # Sample Certificates - Update to include issued_by_id if admin_user exists
        admin_user = User.query.filter_by(username='admin').first()
        if admin_user:
            cert1 = Certificate(resident_id=created_residents[1].id, type="Barangay Clearance", purpose="Job Application", issued_by_id=admin_user.id)
            cert2 = Certificate(resident_id=created_residents[3].id, type="Residency Certificate", purpose="Proof of Address", issued_by_id=admin_user.id)
            db.session.add_all([cert1, cert2])
        else: # Fallback if admin user doesn't exist (less likely with current setup)
             cert1 = Certificate(resident_id=created_residents[1].id, type="Barangay Clearance", purpose="Job Application")
             cert2 = Certificate(resident_id=created_residents[3].id, type="Residency Certificate", purpose="Proof of Address")
             db.session.add_all([cert1, cert2])
        
        # Sample Announcements
        announce1 = Announcement(title="Community Clean-up Drive", content="Join us this Saturday, 8 AM, for a barangay-wide clean-up drive. Meet at the barangay hall.")
        announce2 = Announcement(title="Vaccination Schedule Update", content="COVID-19 booster shots available Mon-Fri, 9 AM to 4 PM. Bring your vaccination card.")
        announce3 = Announcement(title="Basketball League Registration", content="Registration for the Inter-Purok Basketball League is now open until the end of the month.")
        db.session.add_all([announce1, announce2, announce3])
        
        # Sample Inventory Items - Use low_stock_threshold
        med_cat = InventoryCategory.query.filter_by(name='Medicines').first()
        sup_cat = InventoryCategory.query.filter_by(name='Supplies').first()
        # Ensure description is added if the column exists and is needed
        item1 = InventoryItem(name="Paracetamol 500mg", description="Pain reliever and fever reducer", category=med_cat, quantity=100, unit="Tablets", low_stock_threshold=20, expiry_date=datetime.strptime("2025-12-31", "%Y-%m-%d").date())
        item2 = InventoryItem(name="Amoxicillin 250mg/5ml Syrup", description="Antibiotic syrup", category=med_cat, quantity=30, unit="Bottles", low_stock_threshold=10, expiry_date=datetime.strptime("2024-08-31", "%Y-%m-%d").date())
        item3 = InventoryItem(name="Gauze Pads (Sterile)", description="Sterile wound dressing", category=sup_cat, quantity=50, unit="Packs", low_stock_threshold=15)
        item4 = InventoryItem(name="Alcohol 70% Solution", description="Antiseptic solution", category=sup_cat, quantity=25, unit="Bottles (500ml)", low_stock_threshold=5)
        db.session.add_all([item1, item2, item3, item4])
        db.session.commit() # Commit items to get IDs
        
        # Add initial inventory transactions
        admin_user = User.query.filter_by(username='admin').first()
        if admin_user:
            trans1 = InventoryTransaction(item_id=item1.id, quantity=100, transaction_type='in', user_id=admin_user.id, notes='Initial stock')
            trans2 = InventoryTransaction(item_id=item2.id, quantity=30, transaction_type='in', user_id=admin_user.id, notes='Initial stock')
            trans3 = InventoryTransaction(item_id=item3.id, quantity=50, transaction_type='in', user_id=admin_user.id, notes='Initial stock')
            trans4 = InventoryTransaction(item_id=item4.id, quantity=25, transaction_type='in', user_id=admin_user.id, notes='Initial stock')
            db.session.add_all([trans1, trans2, trans3, trans4])
            db.session.commit()
        
        # Sample Appointments
        doctor_user = User.query.filter_by(role='doctor').first()
        if doctor_user and patient1 and patient2:
            appt1 = Appointment(
                patient_id=patient1.id, 
                doctor_id=doctor_user.id, 
                appointment_date=datetime.utcnow().replace(hour=10, minute=0, second=0, microsecond=0) + timedelta(days=1), 
                purpose="Follow-up check for Hypertension"
            )
            appt2 = Appointment(
                patient_id=patient2.id, 
                doctor_id=doctor_user.id, 
                appointment_date=datetime.utcnow().replace(hour=14, minute=30, second=0, microsecond=0) + timedelta(days=2), 
                purpose="Asthma consultation"
            )
            appt3 = Appointment(
                patient_id=patient1.id, 
                doctor_id=doctor_user.id, 
                appointment_date=datetime.utcnow().replace(hour=9, minute=0, second=0, microsecond=0) - timedelta(days=7), 
                purpose="Initial consultation",
                status="completed"
            )
            db.session.add_all([appt1, appt2, appt3])
            db.session.commit() # Commit appointments to get IDs
            
            # Sample Medical Record for the past appointment
            med_rec1 = MedicalRecord(
                patient_id=patient1.id,
                doctor_id=doctor_user.id,
                diagnosis="Essential Hypertension Stage 1",
                treatment="Prescribed Losartan 50mg once daily. Advised lifestyle changes (diet, exercise).",
                prescription="Losartan 50mg #30 tablets, 1 tab OD",
                visit_date=appt3.appointment_date,
                follow_up_date=(appt3.appointment_date + timedelta(days=30)).date(),
                notes="Patient advised to monitor blood pressure daily."
            )
            db.session.add(med_rec1)

        db.session.commit()
        print("Sample data added successfully.")

if __name__ == '__main__':
    app.run(debug=True)
