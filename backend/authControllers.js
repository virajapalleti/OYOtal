import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import Doctor from '../models/doctor.js';
import Patient from '../models/patient.js';
import Pharmacist from '../models/pharmacist.js';
import Admin from '../models/admin.js';

dotenv.config();

const JWT_SECRET = process.env.JWT_SECRET || 'your_secret_key';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '24h';

const signToken = (id, role) => {
  return jwt.sign({ id, role }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
};


export const registerDoctor = async (req, res) => {
  try {
    const hashedPassword = await bcrypt.hash(req.body.password, 12);
    
    const newDoctor = await Doctor.create({
      name: req.body.name,
      email: req.body.email,
      password: hashedPassword,
      specialization: req.body.specialization,
      licenseNumber: req.body.licenseNumber,
      contactNumber: req.body.contactNumber,
      experience: req.body.experience,
      qualification: req.body.qualification,
      associatedHospital: req.body.associatedHospital,
      status: req.body.status,
      availability: req.body.availability,
      languages: req.body.languages,
      consultationFee: req.body.consultationFee,
    });

    const token = signToken(newDoctor._id, 'doctor');

    res.status(201).json({
      status: 'success',
      token,
      data: { doctor: newDoctor },
    });
  } catch (err) {
    res.status(400).json({ status: 'fail', message: err.message });
  }
};


export const registerPatient = async (req, res) => {
  try {
    const hashedPassword = await bcrypt.hash(req.body.password, 12);

    const newPatient = await Patient.create({
      name: req.body.name,
      email: req.body.email,
      password: hashedPassword,
      dateOfBirth: req.body.dateOfBirth,
      gender: req.body.gender,
      bloodGroup: req.body.bloodGroup,
      allergies: req.body.allergies,
      medicalHistory: req.body.medicalHistory,
      isActive: req.body.isActive,
      emergencyContact: req.body.emergencyContact,
    });

    const token = signToken(newPatient._id, 'patient');

    res.status(201).json({
      status: 'success',
      token,
      data: { patient: newPatient },
    });
  } catch (err) {
    res.status(400).json({ status: 'fail', message: err.message });
  }
};


export const registerPharmacist = async (req, res) => {
  try {
    const hashedPassword = await bcrypt.hash(req.body.password, 12);

    const newPharmacist = await Pharmacist.create({
      name: req.body.name,
      email: req.body.email,
      password: hashedPassword,
      licenseNumber: req.body.licenseNumber,
      associatedPharmacy: req.body.associatedPharmacy,
      contactNumber: req.body.contactNumber,
      qualifications: req.body.qualifications,
      status: req.body.status,
    });

    const token = signToken(newPharmacist._id, 'pharmacist');

    res.status(201).json({
      status: 'success',
      token,
      data: { pharmacist: newPharmacist },
    });
  } catch (err) {
    res.status(400).json({ status: 'fail', message: err.message });
  }
};


export const registerAdmin = async (req, res) => {
  try {
    const hashedPassword = await bcrypt.hash(req.body.password, 12);

    const newAdmin = await Admin.create({
      email: req.body.email,
      password: hashedPassword,
    });

    const token = signToken(newAdmin._id, 'admin');

    res.status(201).json({
      status: 'success',
      token,
      data: { admin: newAdmin },
    });
  } catch (err) {
    res.status(400).json({ status: 'fail', message: err.message });
  }
};


export const login = async (req, res) => {
  try {
    const { email, password, role } = req.body;

    if (!email || !password) {
      return res.status(400).json({ status: 'fail', message: 'Please provide email and password' });
    }

    let user;
    switch (role) {
      case 'doctor':
        user = await Doctor.findOne({ email }).select('+password');
        break;
      case 'patient':
        user = await Patient.findOne({ email }).select('+password');
        break;
      case 'pharmacist':
        user = await Pharmacist.findOne({ email }).select('+password');
        break;
      case 'admin':
        user = await Admin.findOne({ email }).select('+password');
        break;
      default:
        return res.status(400).json({ status: 'fail', message: 'Invalid role' });
    }

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ status: 'fail', message: 'Incorrect email or password' });
    }

    const token = signToken(user._id, role);

    res.status(200).json({
      status: 'success',
      token,
    });
  } catch (err) {
    res.status(400).json({ status: 'fail', message: err.message });
  }
};
